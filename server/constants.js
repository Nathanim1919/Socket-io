/**
 * @type {{ADMIN:"ADMIN"; USER:"USER"} as const}
 */

export const UserRolesEnum = {
    ADMIN:"ADMIN",
    USER:"USER"
};

export const AvailableUsersRole = Object.values(UserRolesEnum);

/**
 * @type {{GOOGLE:"GOOGLE"; GITHUB:"GITHUB"; EMAIL_PASSWORD:"EMAIL_PASSWORD"} as const}
 */

export const UserLoginType = {
    GOOGLE:"GOOGLE",
    GITHUB:"GITHUB",
    EMAIL_PASSWORD:"EMAIL_PASSWORD"
}

export const AvailableSocialLogins = Object.values(UserLoginType);