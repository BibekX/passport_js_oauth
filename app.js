//Requires modules
// const https = require("https");
// const fs = require("fs");
const express = require("express");
const { engine } = require("express-handlebars");
const knexFile = require("./knexfile").development;
const knex = require("knex")(knexFile);
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local").Strategy;
// const FacebookStrategy = require("passport-facebook").Strategy;
// const GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;

const port = 3000;
require("dotenv").config();

//Set up modules
const app = express();
app.use(express.urlencoded({ extended: false }));
app.engine("handlebars", engine());
app.set("view engine", "handlebars");

app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

//Middleware to check if the user is authenticated
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function notLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}

//Set up Local Strategy

//Signup
passport.use(
  "local-signup",
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      let user = await knex("users").where({ email }).first();
      console.log("user", user);
      //   knex.select("*").from("users")
      if (user) {
        return done(null, false);
      }
      const hash = await bcrypt.hash(password, 10);
      let newUser = {
        email, //b@b
        password: hash, //2@10a3e3p...
      };
      const id = await knex("users").insert(newUser).returning("id"); //[{id: 4}]
      newUser.id = id[0].id; //id[0] => {id: 4}     id[0].id => 4
      return done(null, newUser);
    }
  )
);

//Login
passport.use(
  "local-login",
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      const user = await knex("users").where({ email }).first();
      if (!user) {
        return done(null, false);
      }
      const result = await bcrypt.compare(password, user.password);
      if (result) {
        return done(null, user);
      }
      return done(null, false);
    }
  )
);

//Facebook Strategy
// passport.use(
//   "facebook",
//   new FacebookStrategy(
//     {
//       clientID: process.env.FACEBOOK_APP_ID,
//       clientSecret: process.env.FACEBOOK_SECRET,
//       callbackURL: "https://localhost:3000/auth/facebook/callback",
//       profileFields: ["id", "email", "name"],
//     },
//     async (accessToken, refreshToken, profile, done) => {
//       try {
//         const user = await knex("users")
//           .where({ facebook_id: profile.id })
//           .first();
//         if (!user) {
//           let newUser = {
//             facebook_id: profile.id,
//             email: profile._json.email,
//           };
//           const id = await knex("users").insert(newUser).returning("id");
//           newUser.id = id[0].id;
//           return done(null, newUser);
//         } else {
//           return done(null, user);
//         }
//       } catch (err) {
//         console.log(err);
//         return done(err, false);
//       }
//     }
//   )
// );

//Google Strategy
// passport.use(
//   "google",
//   new GoogleStrategy(
//     {
//       clientID: process.env.GOOGLE_ID,
//       clientSecret: process.env.GOOGLE_SECRET,
//       callbackURL: "https://localhost:3000/auth/google/callback",
//     },
//     async (accessToken, refreshToken, profile, done) => {
//       try {
//         const user = await knex("users")
//           .where({ google_id: profile.id })
//           .first();
//         if (!user) {
//           let newUser = {
//             google_id: profile.id,
//             email: profile._json.email,
//           };
//           const id = await knex("users").insert(newUser).returning("id");
//           newUser.id = id[0].id;
//           return done(null, newUser);
//         } else {
//           return done(null, user);
//         }
//       } catch (err) {
//         console.log(err);
//         return done(err, false);
//       }
//     }
//   )
// );

//Serialize
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//Deserialize
passport.deserializeUser(async (id, done) => {
  const user = await knex("users").where({ id }).first();
  if (!user) {
    return done(null, false);
  }
  return done(null, user);
});

//Handle Get request
app.get("/", isLoggedIn, (req, res) => {
  res.render("secret", {
    title: "Secret",
  });
});

app.get("/signup", notLoggedIn, (req, res) => {
  res.render("signup", {
    title: "Sign Up",
  });
});

app.get("/login", notLoggedIn, (req, res) => {
  res.render("login", {
    title: "Login",
  });
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return err;
    }
    res.redirect("/login");
  });
});

//Handle Post request
app.post(
  "/signup",
  passport.authenticate("local-signup", {
    successRedirect: "/login",
    failureRedirect: "/signup",
  })
);

app.post(
  "/login",
  passport.authenticate("local-login", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

//Handle Facebook Login
// app.get(
//   "/auth/facebook",
//   passport.authenticate("facebook", {
//     scope: ["email", "public_profile"],
//   })
// );

// app.get(
//   "/auth/facebook/callback",
//   passport.authenticate("facebook", {
//     successRedirect: "/",
//     failureRedirect: "/login",
//   })
// );

//Handle Google Login
// app.get(
//   "/auth/google",
//   passport.authenticate("google", {
//     scope: ["email", "profile"],
//   })
// );

// app.get(
//   "/auth/google/callback",
//   passport.authenticate("google", {
//     successRedirect: "/",
//     failureRedirect: "/login",
//   })
// );

// const options = {
//   cert: fs.readFileSync("./localhost.crt"),
//   key: fs.readFileSync("./localhost.key"),
// };

app.listen(port, () => console.log(`Listening to port ${port}`));
// https
//   .createServer(options, app)
//   .listen(3000, () => console.log(`Listening to port ${port}`));
