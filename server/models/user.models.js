const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const {
  UserLoginType,
  AvailableSocialLogins,
  AvailableUsersRole,
  UserRolesEnum,
} = require("../constants");

const userSchema = new Schema(
  {
    avatar: {
      type: {
        url: String,
        localPath: String,
      },
      default: {
        url: "https://via.placeholder.com/200x200.png",
        localPath: "",
      },
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    role: {
      type: String,
      enum: AvailableUsersRole,
      default: UserRolesEnum.USER,
      required: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
    },
    loginType: {
      type: String,
      enum: AvailableSocialLogins,
      default: UserLoginType.EMAIL_PASSWORD,
    },

    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    refreshToken: {
      type: String,
    },
    forgotPasswordToken: {
      type: String,
    },
    forgotPasswordExpiry: {
      type: String,
    },
    emailVerficationToken: {
      type: String,
    },
    emailVerificationExpiry: {
      type: Date,
    },
  },
  { timestamps: true }
);

/**
 * @description Method responsible for hashing password before saving it to database
 */

userSchema.pre('save', async function(next){
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
})

/**
 * @param {*} password 
 * @description Method responsible for comparing password with the hashed password in database 
 * @returns 
 */
userSchema.methods.isPasswordCorrect = async (password) =>
  await bcrypt.compare(password, this.password);

/**
 * @description Method responsible for generating access token
 * @returns 
 */
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      role: this.role,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.USER_TOKEN_EXPIRY }
  );
};


/**
 * @description Method responsible for generating refresh token
 * @returns 
 */
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env. USER_REFRESH_TOKEN_EXPIRY }
  );
};

/**
 * @description Method responsible for generating tokens for email verfication, password reset etc.
 */

userSchema.methods.generateTemporaryToken = function () {
  // this token should be client facing
  // for example: for email verfication unHashedToken should be sent to user's email
  const unHashedToken = crypto.randomBytes(20).toString("hex");

  // this token should be stored in database to compare at the time of verification
  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");

  // this is the expiry time for the token (20 minutes)
  const tokenExpiry = Date.now() + process.env.USER_TEMPORARY_TOKEN_EXPIRY;

  return {
    unHashedToken,
    hashedToken,
    tokenExpiry,
  };
};

export const User = mongoose.model('User', userSchema);