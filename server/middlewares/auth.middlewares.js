const AvailableUserRoles = require("../constants.js");
const User = require("../models/user.models.js");
const { ApiError } = require("../utils/ApiError.js");
const asyncHandler = require("../utils/asyncHandler.js");
const jwt = require("jsonwebtoken");

const verfiyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new Error("Unauthorized request");
  }

  try {
    const decodeToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decodeToken?._id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
    );

    if (!user) {
      // Client should make a request to /api/v1/users/refresh-token if they have refreshToken present in their cookie
      // Then they will get a new access token which will allow them to refresh the access token without logging out the user
      throw new Error("Invalid token")
    }

    req.user = user;
    next();
  } catch (error) {
    console.log(error);
  }
});



const verifyPermission = (roles = []) => 
    asyncHandler(async (req, res, next) => {
        if (!req.user?._id) {
            throw new Error("Unauthorized request");
        }

        if (roles.includes(req.user?.role)){
            next()
        } else {
            throw new Error("You are not allowed to perform this action");
        }
    })


module.exports = {
  verfiyJWT,
  verifyPermission
}