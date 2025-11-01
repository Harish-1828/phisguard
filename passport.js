require("dotenv").config();
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcryptjs");
const User = require("./models/Users");

// -----------------------------
// 🧩 Local Strategy (email + password)
// -----------------------------
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user)
          return done(null, false, { message: "Incorrect email" });

        if (!user.password)
          return done(null, false, { message: "Please log in with Google" });

        const match = await bcrypt.compare(password, user.password);
        if (!match)
          return done(null, false, { message: "Incorrect password" });

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// -----------------------------
// 🌐 Google OAuth Strategy
// -----------------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user with this Google ID already exists
        let user = await User.findOne({ googleId: profile.id });
        if (user) return done(null, user);

        // If not, check if user with same email exists and link Google ID
        const email = profile.emails?.[0]?.value;
        if (email) {
          const existingEmailUser = await User.findOne({ email });
          if (existingEmailUser) {
            existingEmailUser.googleId = profile.id;
            await existingEmailUser.save();
            return done(null, existingEmailUser);
          }
        }

        // Otherwise create a new user
        const newUser = new User({
          googleId: profile.id,
          name: profile.displayName,
          email,
        });
        await newUser.save();
        done(null, newUser);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// -----------------------------
// 🔒 Serialize & Deserialize
// -----------------------------
passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

module.exports = passport;
