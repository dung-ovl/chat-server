const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");

const User = require("../models/user");

const filterObj = require("../utils/filterObj");

const signToken = (userId) => jwt.sign({ id: userId }, process.env.JWT_SECRET);
exports.register = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  const filteredBody = filterObj(
    req.body,
    "firstName",
    "lastName",
    "email",
    "password"
  );

  const existing_user = await User.findOne({ email: email });

  if (existing_user && existing_user.verified) {
    return res.status(400).json({
      status: "fail",
      message: "User already exists",
    });
  } else if (existing_user) {
    await User.findOneAndUpdate({ email: email }, filteredBody, {
      new: true,
      validateModifiedOnly: true,
    });

    req.userId = existing_user._id;
    next();
  } else {
    const user = await User.create(filteredBody);

    req.userId = user._id;
    next();
  }
};

exports.sendOTP = async (req, res, next) => {
  const { userId } = req;
  const new_otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
  });

  const otp_expires = Date.now() + 10 * 60 * 1000;

  await User.findByIdAndUpdate(userId, {
    otp: new_otp,
    otpExpires: otp_expires,
  });

  res.status(200).json({
    status: "success",
    message: "OTP sent successfully",
  });
};

exports.verifyOTP = async (req, res, next) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email, otpExpires: { $gt: Date.now() } });

  if (!user) {
    res.status(400).json({
      status: "fail",
      message: "Invalid OTP or OTP expired",
    });
  }

  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "fail",
      message: "Invalid OTP",
    });
  }

  user.verified = true;
  user.otp = undefined;
  await user.save({ new: true, validateModifiedOnly: true });

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "User verified successfully",
    token,
  });
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      status: "fail",
      message: "Please provide email and password",
    });
  }

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return res.status(401).json({
      status: "fail",
      message: "Incorrect email or password",
    });
  }

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "Logged in successfully",
    token,
  });
};

exports.protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    return res.status(401).json({
      status: "fail",
      message: "You are not logged in! Please log in to get access",
    });
  }

  const decoded = await promisfy(jwt.verify)(token, process.env.JWT_SECRET);

  const this_user = await User.findById(decoded.userId);

  if (!this_user) {
    return res.status(401).json({
      status: "fail",
      message: "The user belonging to this token does no longer exist",
    });
  }

  if (this_user.changedPasswordAfter(decoded.iat)) {
    return res.status(401).json({
      status: "fail",
      message: "User recently changed password! Please log in again",
    });
  }

  req.user = this_user;
  next();
};

exports.forgotPassword = async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError("There is no user with email address.", 404));
  }

  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it to user's email
  try {
    const resetURL = `https://tawk.com/auth/reset-password/${resetToken}`;
    // TODO => Send Email with this Reset URL to user's email address

    res.status(200).json({
      status: "success",
      message: "Token sent to email!",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError("There was an error sending the email. Try again later!"),
      500
    );
  }
};

exports.resetPassword = async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 3) Update changedPasswordAt property for the user
  // 4) Log the user in, send JWT
  createSendToken(user, 200, req, res);
};
