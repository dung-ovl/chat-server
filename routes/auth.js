const router = require("express").Router();

const authController = require("../controllers/auth");

router.post("/login", authController.login);

router.post("/register", authController.register);

router.post("/send-otp", authController.sendOTP);

router.post("/verify-otp", authController.verifyOTP);
module.exports = router;
