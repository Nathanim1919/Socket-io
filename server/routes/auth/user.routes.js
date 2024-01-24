const express = require("express");
const router = express.Router();
const {UserRolesEnum} = require("../../constants.js");
const {
    assignRole,
    changeCurrentPassword,
    forgotPasswordRequest,
    getCurrentUser,
    handleSocialLogin,
    loginUser,
    logoutUser,
    refreshAccessToken,
    registerUser,
    resendEmailVerification,
    resetForgottenPassword,
    // updateUserAvatar,
    verifyEmail,
} = require("../../controllers/user.controllers");

const {
  verfiyJWT,
  verifyPermission,
} = require("../../middlewares/auth.middlewares.js");

const {
  userAssignRoleValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userLoginValidator,
  registerValidator,
  userResetForgotPasswordValidator,
} = require("../../validators/auth/user.validators.js");

const validate = require("../../validators/validate.js");
const passport = require("passport");

// Unsecured Route
router.route("/register").post(registerValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, loginUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/verify-email/:verificationToken").get(verifyEmail);

router
  .route("/forgot-password")
  .post(userForgotPasswordValidator(), validate, forgotPasswordRequest);
router
    .route("/reset-password/:resetToken").post(
    userResetForgotPasswordValidator(),
    validate,
    resetForgottenPassword
  );
  
// secured routes
router
    .route("/logout").post(verfiyJWT, logoutUser);
router
    .route("/current-user").get(verfiyJWT, getCurrentUser);
router
  .route("/change-password")
  .post(
    verfiyJWT,
    userChangeCurrentPasswordValidator,
    validate,
    changeCurrentPassword
  );
router
  .route("/resend-email-verification")
  .post(verfiyJWT, resendEmailVerification);
router
  .route("/assign-role/:userId")
  .post(
    verfiyJWT,
    verifyPermission([UserRolesEnum.ADMIN]),
    userAssignRoleValidator(),
    validate,
    assignRole
  );
router.route("/google").get(
  passport.authenticate("google", {
    scope: ["profile", "email"],
  }),
  (req, res) => {
    res.send("redirected to google...");
  }
);

router.route("/github").get(
  passport.authenticate("github", {
    scope: ["profile", "email"],
  }),
  (req, res) => {
    res.send("redirecting to github...");
  }
);

router
  .route("/google/callback")
  .get(passport.authenticate("google"), handleSocialLogin);

router
  .route("/github/callback")
  .get(passport.authenticate("github"), handleSocialLogin);

module.exports = router;