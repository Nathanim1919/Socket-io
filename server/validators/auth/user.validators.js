const { body, param } = require("express-validator");
const { AvailableUsersRole } = require("../../constants");

const registerValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("Username must be lowercase")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),
    body("password").trim().notEmpty().withMessage("Password is required"),
    body("role")
      .optional()
      .isIn(AvailableUsersRole)
      .withMessage("Invalid user role"),
  ];
};


const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Email is required"),
    body("username").optional(),
    body("password").notEmpty().withMessage("Password is required"),
  ];
};


const userChangeCurrentPasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("Old Password is required"),
    body("newPassword").notEmpty().withMessage("New password is required"),
  ];
};


const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
  ];
};


const userResetForgotPasswordValidator = () => {
    return [
        body("newPassword")
            .notEmpty().withMessage("Password is required")
    ]
}

const userAssignRoleValidator = () => {
    return [
        body("role")
            .optional()
            .isIn(AvailableUsersRole)
            .withMessage("Invalid user role")
    ]
}

module.exports = {
    registerValidator,
    userLoginValidator,
    userAssignRoleValidator,
    userResetForgotPasswordValidator,
    userForgotPasswordValidator,
    userChangeCurrentPasswordValidator
}