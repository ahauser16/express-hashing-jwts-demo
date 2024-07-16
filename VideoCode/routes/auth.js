/** Routes for demonstrating authentication in Express. */

const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { ensureLoggedIn, ensureAdmin } = require("../middleware/auth");

router.get('/', (req, res, next) => {
  res.send("APP IS WORKING!!!")
})

//The function is designed to register a new user by inserting their username and hashed password into a users table in the database. If the insertion fails due to a specific error, the error code is used to determine the appropriate response. If the error code is 23505, the username is already taken, and the user is prompted to choose another. If the error code is not 23505, the error is passed to the next error-handling middleware.
router.post('/register', async (req, res, next) => {
  //Error Handling: The `try...catch` block is used to catch any errors that occur during the execution of the asynchronous database query. If an error occurs, it is caught by the `catch` block, and the error object `e` is examined.
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    // hash password
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    // save to db
    const results = await db.query(`
      INSERT INTO users (username, password)
      VALUES ($1, $2)
      RETURNING username`,
      [username, hashedPassword]);
    return res.json(results.rows[0]);
    //Handling Specific Error Codes: The `catch` block checks if the error code (`e.code`) is `23505`. If it is, this indicates that the username being registered already exists in the database. The application then creates a new `ExpressError` with a message indicating that the username is taken and sends this error to the next middleware in the Express chain by calling `next(new ExpressError("Username taken. Please pick another!", 400))`. This results in a `400 Bad Request` response being sent back to the client with the message "Username taken. Please pick another!". If the error code is not 23505, the catch block calls next(e) to pass the error to the next error-handling middleware.
  } catch (e) {
    //PostgreSQL Error Code `23505`: The error code `23505` corresponds to a "unique_violation" error in PostgreSQL. This error occurs when an attempt is made to insert or update a row in such a way that it would violate a uniqueness constraint on a table. In the context of this application, it specifically occurs when a user tries to register with a username that already exists in the database.

    //General Error Handling: If the error code is not `23505` or if any other type of error occurs, the original error `e` is passed to the next middleware by calling `next(e)`. This allows for generic error handling elsewhere in the application, where more detailed logging or user-friendly error messages might be generated.
    if (e.code === '23505') {
      return next(new ExpressError("Username taken. Please pick another!", 400));
    }
    return next(e)
  }
});

//This function is an Express route handler for the /login endpoint, designed to authenticate users. It uses asynchronous operations, error handling, and JSON Web Tokens (JWT) for authentication.

//Defines an asynchronous POST route handler for the `/login` endpoint. `req` is the request object, `res` is the response object, and `next` is a function to pass control to the next middleware.
router.post('/login', async (req, res, next) => {
  //Starts a try block to catch and handle any errors that occur within the block.
  try {
    //Destructures the `username` and `password` from the request body. This is where the user submits their credentials.
    const { username, password } = req.body;
    //Checks if either `username` or `password` is not provided.
    if (!username || !password) {
      //If either `username` or `password` is missing, it throws a custom error (ExpressError) indicating that both fields are required, with a 400 status code for Bad Request.
      throw new ExpressError("Username and password required", 400);
    }
    //Asynchronously executes a SQL query to select the `username` and `password` from the `users` table where the `username` matches the provided username.  The `sql` statement uses a parameterized query to prevent SQL injection attacks.
    const results = await db.query(
      `SELECT username, password 
       FROM users
       WHERE username = $1`,
      [username]);  //The actual value to replace $1 in the query, which is the username provided by the user.
    //Retrieves the first row from the query results, which should contain the user's data if the username exists in the database.
    const user = results.rows[0];
    //Checks if the user object exists, meaning the query found a user with the provided username.
    if (user) {
      //Asynchronously compares the provided password with the hashed password stored in the database using bcrypt.the `compare()` function returns a promise that resolves to a boolean value indicating whether the passwords match.
      if (await bcrypt.compare(password, user.password)) {
        //If the password matches, it generates a JWT token signed with the `SECRET_KEY`, including the `username` in the payload. The token is then sent back to the client in the response.
        const token = jwt.sign({ username }, SECRET_KEY);
        //Responds with a JSON object containing a success message and the JWT token.
        return res.json({ message: `Logged in!`, token })
      }
    }
    //If either the user does not exist or the password does not match, it throws a custom error indicating invalid username/password with a 400 status code.
    throw new ExpressError("Invalid username/password", 400);
    //Catches any errors that occurred within the try block.
  } catch (e) {
    //Passes the error to the next error handling middleware in Express.
    return next(e);
  }
})

router.get('/topsecret',
  ensureLoggedIn,
  (req, res, next) => {
    try {
      return res.json({ msg: "SIGNED IN! THIS IS TOP SECRET.  I LIKE PURPLE." })

    } catch (e) {
      return next(new ExpressError("Please login first!", 401))
    }
  })

router.get('/private', ensureLoggedIn, (req, res, next) => {
  return res.json({ msg: `Welcome to my VIP section, ${req.user.username}` })
})

router.get('/adminhome', ensureAdmin, (req, res, next) => {
  return res.json({ msg: `ADMIN DASHBOARD! WELCOME ${req.user.username}` })
})


module.exports = router;

