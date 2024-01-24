const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const {User} = require("../models/user.models");

const {
  sendEmail,
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
} = require("../utils/mail");

const { UserLoginType, UsercRoleEnum } = require("../constants");
const asyncHandler = require("../utils/asyncHandler");
const Apiresponse = require("../utils/ApiResponse");

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // attach refresh token to the user document in the database
    user.refreshToken = refreshToken;

    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (err) {
    console.log(
      "Something went wrong while generating the access token: ",
      err
    );
  }
};

// User register controller
const registerUser = asyncHandler(async (req, res, next) => {
  const { email, username, password, role } = req.body;

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new Error("User already exists");
  }

  const user = await User.create({
    email,
    username,
    password,
    isEmailVerified: false,
    role: role || UsercRoleEnum.USER,
  });

  /**
   * unHashedToken: unHashed token is something we will send to the user's email
   * hashedToken: hashed token is something we will save in the database
   * tokenExpiry: Expiry to be checked before validating the incoming token
   */

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationTokenExpiresAt = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailGenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get(
        "host"
      )}/api/v1/auth/verify-email/${unHashedToken}`
    ),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerficationToken -emailVerificationExpiry"
  );

  if (!createdUser) {
    throw new Error("User not found");
  }

  return res
    .status(201)
    .json(
      new Apiresponse(
        200,
        { user, createdUser },
        "User created successfully. Please verify your email to continue"
      )
    );
});

// User login controller
const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  if (!email && !username) {
    throw new Error("Please provide email or username");
  }

  const user = await User.findOne({
    $or: [{ email }, { username }],
  });

  if (!user) {
    throw new Error("User not found");
  }

  if (user.loginType !== UserLoginType.EMAIL_PASSWORD) {
    // if user is registered with some other method, we will ask him/her to use the same method as registered.
    // This shows that if user is registered with methods other than email password, he/she will not be able to login with email password. Which makes password field redundant for SSO users.
    throw new Error(
      "You have previously registered using " +
        user.loginType?.toLowerCase() +
        ". Please login using the same method."
    );
  }

  // Compare the incoming password with the hashed password
  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new Error("Invalid credentials");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  // get the user details without password and refresh token
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  return res
    .status(200)
    .cookie("accessToken", accessToken)
    .cookie("refreshToken", refreshToken)
    .json(
      new Apiresponse(
        200,
        { user: loggedInUser, accessToken, refreshToken }, // send access and refresh token in response if client decides to save them by themselves
        "User logged in successfully"
      )
    );
});

// User Logout controller (clears the cookies)
const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    { new: true }
  );

  // TODO: Add more options to make cookie more secure and reliable
  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new Apiresponse(200, {}, "User logged out successfully"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  if (!verificationToken) {
    throw new Error("Email verfication token is missing");
  }

  // generate a hash from the token that we are receiving
  let hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  /**
   * While registering the user, same time when we are sending the verfication email,
   * we are also saving the hashed token and its expiry in the database.
   * we will try to find the user with the hashed token generated by recievied token.
   * If user is found, we will check if the token is expired or not.
   * If token is not expired, we will update the user's isEmailVerified field to true.
   * If token is expired, we will throw an error.
   * If user is not found, we will throw an error.
   */

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationTokenExpiresAt: { $gt: Date.now() },
  });

  if (!user) {
    throw new Error("Invalid token or token expired");
  }

  // if we found the user that means the token is valid and not expired
  // Now we can remove the associated email token and expiry date as we no longer need them
  user.emailVerificationToken = undefined;
  emailVerificationTokenExpiry = undefined;

  // Tun on the isEmailVerified flag
  user.isEmailVerified = true;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(
      new Apiresponse(
        200,
        { isEmailVerified: true },
        "Email verified successfully"
      )
    );
});

/**
 * This controller is called when user is logged in and he has snackbar that says "Your email is not verified. Please verify your email to continue"
 * In case he did not get the email or the email verification token is expired, he can click on the button that says "Resend verification email"
 * he will be able to resend the token while he is logged in.
 * This controller will send the verification email again to the user's email address.
 */

const resendEmailVerification = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    throw new Error("User not found");
  }

  // if user is already verified, we will throw an error
  if (user.isEmailVerified) {
    throw new Error("Email already verified");
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken(); // genearate email verfication credentials

  user.emailVerificationToken = hashedToken;
  user.emailVerificationTokenExpiresAt = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailGenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get(
        "host"
      )}/api/v1/auth/verify-email/${unHashedToken}`
    ),
  });

  return res
    .status(200)
    .json(new Apiresponse(200, {}, "Verification email sent successfully"));
});

/**
 * This controller is called when user clicks on "Forgot password" button on the login page.
 * This controller will send a reset password email to the user's email address.
 */

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;

  // Get email from the client and check if the user exists
  const user = await User.findOne({ email });

  if (!user) {
    throw new Apiresponse(404, "User not found", []);
  }

  // generate a temporary token and save it in the database
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken(); // generate password reset creds

  // save the hashed version  of the token and expiry in the database
  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordTokenExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  // send the password reset email to the user's email address
  await sendEmail({
    email: user?.email,
    subject: "Reset your password",
    mailGenContent: forgotPasswordMailgenContent(
      user?.username,
      // ! NOTE: Following link should be the link of the frontend page responsible to request password reset
      // ! Frontend will send the below token with the new password in the request body to the backend reset password endpoint
      // * Ideally take the url from the .env file which should be teh url of the frontend
      `${req.protocol}://${req.get(
        "host"
      )}/api/v1/auth/reset-password/${unHashedToken}`
    ),
  });
  return res
    .status(200)
    .json(new Apiresponse(200, {}, "Password reset email sent successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken ||
    req.headers["x-refresh-token"] ||
    req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new Error("Refresh token missing");
  }

  // generate a hash from the token that we are receiving

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.JWT_SECRET
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new Error("Invalid Refresh Token");
    }

    // check if incoming refresh token is same as the one saved in the database
    // This shows that the refresh token is used or not
    // Once it is used, we are replacing the refresh token with a new one

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new Error("Invalid refresh token");
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken)
      .cookie("refreshToken", newRefreshToken)
      .json(
        new Apiresponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new Error("Invalid refresh token");
  }
});

const resetForgottenPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  // Create a hash of the incoming reset token
  let hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // See if user with hash similar to resetToken exists
  // If yes then check if token expiry is greater than current date

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });

  // If either of the one is false that means the token is invalid or expired
  if (!user) {
    throw new Error("Token is invalid or expired");
  }

  // if everything is ok and token id valid
  // reset the forgot password token and expiry
  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;

  // set the provided password as the new password
  user.password = newPassword;
  await user.save({ validateBeforeSave: false });
  return res
    .status(200)
    .json(new Apiresponse(200, {}, "Password reset successfully"));
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);

  //  check the old password
  const isPasswordValid = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordValid) {
    throw new Error("Invalid old password");
  }

  // assign new password in plain text
  // we have a pre save method attached to user schema which automatically hashes the password whenever added/modified
  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new Apiresponse(200, {}, "Password changed successfully"));
});

const assignRole = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { role } = req.body;
  const user = await User.findById(userId);

  if (!user) {
    throw new Error("User does not exist");
  }

  user.role = role;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new Apiresponse(200, {}, "Role changed for the user"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
  .status(200)
  .json(new Apiresponse(200, req.user, "Current user fetched successfully"));
});

const handleSocialLogin = asyncHandler(async (req, res) => {

})


module.exports = {
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
};