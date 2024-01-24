const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const { User } = require("../models/user.models");
const { UserLoginType, UserRolesEnum } = require("../constants");
const { Strategy: GitHubStrategy } = require("passport-github2");
const Apiresponse = require("../utils/ApiResponse");
const { ApiError } = require("../utils/ApiError");

try {
  passport.serializeUser((user, next) => {
    next(null, user._id);
  });

  passport.deserializeUser(async (id, next) => {
    try {
      const user = await User.findById(id);
      if (user) next(null, user); //return user of exists
      else next(new ApiError(404, "User does not exist"), null);
    } catch (error) {
      next(
        new ApiError(
          500,
          "Something went wrong while deserializing the user. Error: " + error
        ),
        null
      );
    }
  });

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
      },

      async (_, __, profile, next) => {
        // Check if the user with email alreasy exist
        const user = await User.findOne({ email: profile._json.email });

        if (user) {
          // if user exists, check if user has registered with the GOOGLE SSO(GOOGLE SINGLE SIGN ON)
          if (user.UserLoginType !== UserLoginType.GOOGLE) {
            // if user is registered with some other method, we will ask him/her to use the same method as registered
            // TODO: we can redirect user to appropriate frontedn urls which will show users what went wrong instead of sending response from the backend
            next(
              new ApiError(
                400,
                "You have previousl registred using " +
                  user.UserLoginType?.toLowerCase()?.split("_").join(" ") +
                  ". Please use the " +
                  user.UserLoginType?.toLowerCase()?.split("_").join(" ")
              ),

              null
            );
          } else {
            // if the user is registered with the same login method we will send the saved user
            next(null, user);
          }
        } else {
          // If user with email does not exists, means the user is coming for the first time
          const createdUser = await User.create({
            email: profile._json.email,
            password: profile._json.sub, //Set user's password as sub (coming from the google)
            username: profile._json.email?.split("@")[0], // as email is unique, this username will be unique
            isEmailVerified: true, // email will be already verified
            role: UserRolesEnum.USER,
            avatar: {
              url: profile._json.picture,
              locationPath: "",
            }, // set avatar as user's google picture
            UserLoginType: UserLoginType.GOOGLE,
          });

          if (createdUser) next(null, createdUser);
          else
            next(new ApiError(500, "Error while registering the user"), null);
        }
      }
    )
  );

//  next will be GIT HUB authentication strategy
} catch (error) {
  console.error("PASSPORT ERROR: ", error);
}