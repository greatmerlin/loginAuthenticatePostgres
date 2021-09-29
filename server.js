const express = require('express');
const app = express();
const { pool } = require("./dbConfig.js");
const bcrypt = require("bcrypt");
const flash = require("express-flash");
const session = require("express-session");

const passport = require("passport");
const initializePassport = require("./passportConfig.js"); // import this function from passconfig file
initializePassport(passport);

const PORT = process.env.PORT || 4000;

// MIDDLEWARE

// Parses details from a form
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));

app.use(
    session({
        // Key we want to keep secret which will encrypt all of our information
        secret: process.env.SESSION_SECRET,
        // Should we resave our session variables if nothing has changes which we dont want to do  
        resave: false,
        // Save empty value if there is no vaue which we do not want to do
        saveUninitialized: false
    })
);

// with this we display our flash messages
app.use(flash());

// pass in middleware
// Funtion inside passport which initializes passport
app.use(passport.initialize());
// Store our variables to be persisted across the whole session. Works with app.use(Session) above
app.use(passport.session());

// HANDLE GET IN THE PAGES --------------------------------------------------------------------------------------------

app.get('/', (req, res) => {
    res.render("index");
});

app.get('/users/register', checkAuthenticated,  (req, res) => {
    res.render("register");
});

app.get('/users/login', checkAuthenticated,  (req, res) => {
    res.render("login");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
    console.log(req.isAuthenticated());
    res.render("dashboard", { user: req.user.name });
  });

  app.get("/users/logout", (req, res) => {
    req.logout();
    res.render("index", { message: "You have logged out successfully" });
  });

// POST ------------------------------------------------------------------------------------------------------------

// HANDLE FORM POST IN REGISTER PAGE

app.post("/users/register", async (req, res) => {
    let { name, email, password, password2 } = req.body;

    console.log({
        name, email, password, password2
    });

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: "Please enter all fields" });
    }

    if (password.length < 6) {
        errors.push({ message: "Password must be a least 6 characters long" });
    }

    if (password !== password2) {
        errors.push({ message: "Passwords do not match" });
    }

    if (errors.length > 0) {
        res.render("register", { errors, name, email, password, password2 });
    } else {
        hashedPassword = await bcrypt.hash(password, 10); // 10 is the number of rounds for the hash
        console.log(`this is the hashed pw ${hashedPassword}`);
        // Validation passed
        // check if the email already exists in our db
        pool.query(
            `SELECT * FROM users
            WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                    console.log(err);
                }
                console.log(` !!!!!!!! if this is greater than 1 then the account already exists:  ${results.rows.length}`);

                if (results.rows.length > 0) {
                    // find a way to show a validation at the page ----------------------> done
                    errors.push({ message: "Email already registered" });
                    res.render("register", { errors }); // this will render the register page again showing the errors (props)



                } else {

                    // if the e-mail does not already exist in the db, we can add a new user to the db

                    pool.query(
                        `INSERT INTO users (name, email, password)
                    VALUES ($1, $2, $3)
                    RETURNING id, name, email,  password`,
                        [name, email, hashedPassword], // these are the values $1 $2 $3, we give them names
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash("success_msg", "You are now registered. Please log in");
                            res.redirect("/users/login"); // redirects to the login page
                        }
                    );
                }
            }
        );
    }

});

// this takes the user variable (ejs) from dashboard <%= user %> ----> is like props in react


// this is for the cookies check if the user exists, if he exists redirect to dashboard -----------------------------------------

app.post(
    "/users/login",
    passport.authenticate("local", {
      successRedirect: "/users/dashboard",
      failureRedirect: "/users/login",
      failureFlash: true
    })
  );

  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect("/users/dashboard");
    }
    next();
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/users/login");
  }

  //------------------------------------------------------------------------------------------------------------------------------

app.listen(PORT, () => {
    console.log(`Server running on Port: ${PORT}`);
});