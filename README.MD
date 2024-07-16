# Notes on this project code

## `auth.js`

### JSON Web Token explaination

A JWT (JSON Web Token) is a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT are encoded as a JSON object that is used as the payload of a JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure, enabling the claims to be digitally signed or integrity-protected with a Message Authentication Code (MAC) and/or encrypted.

#### JWT Structure

A JWT is composed of three parts, separated by dots `.` :

1. Header
2. Payload
3. Signature

##### 1. Header
The header typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA.

Best Practices for Header:

- Specify Algorithm Explicitly: Always specify the algorithm explicitly to avoid algorithm manipulation attacks.
Avoid Using none Algorithm: The none algorithm should be avoided as it indicates that the token is unsigned, making it vulnerable to tampering.

##### 2. Payload
The payload contains the claims. Claims are statements about an entity (typically, the user) and additional data. There are three types of claims: registered, public, and private claims.

Best Practices for Payload:

- Minimize Payload Size: Only include essential information to keep the token size small. This is particularly important for network efficiency.
- Use Registered Claims Sparingly: Registered claim names are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims. Include only necessary registered claims like iss (issuer), exp (expiration time), sub (subject), etc.
- Avoid Sensitive Information: Do not include sensitive information in the payload, as base64 encoding used in JWT is not an encryption method and can be easily decoded.
- Expiration Time: Always include an expiration time (exp) to reduce the risk of token theft and replay attacks.

##### 3. Signature
To create the signature part you have to take the `encoded header`, the `encoded payload`, a `secret`, the `algorithm` specified in the header, and `sign` that.

Best Practices for Signature:

- Use Strong Secret Keys: For HMAC algorithms, use a strong secret key that is not easily guessable. For RSA or ECDSA, use a strong private key.
- Keep the Secret Safe: The security of the token relies on the secrecy of the secret key. Never expose it or hard-code it in your applications.
- Regularly Rotate Secrets: Regularly change your secret keys to mitigate the impact of a potentially compromised key.

##### 4. Conclusion
- JWTs are a powerful tool for securely transmitting information between parties as JSON objects. By adhering to best practices in constructing and handling each part of the JWT, you can ensure the security and integrity of the tokens in your applications.

### `/login` route

This function is an Express route handler for the `/login` endpoint, designed to authenticate users. It uses asynchronous operations, error handling, and JSON Web Tokens (JWT) for authentication.

```
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    const results = await db.query(
      `SELECT username, password
       FROM users
       WHERE username = $1`,
      [username]);  //The actual value to replace $1 in the query, which is the username provided by the user.
    const user = results.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username }, SECRET_KEY);
        return res.json({ message: `Logged in!`, token })
      }
    }
    throw new ExpressError("Invalid username/password", 400);
  } catch (e) {
    return next(e);
  }
})
```

1. `router.post('/login', async (req, res, next) => {`

Defines an asynchronous POST route handler for the `/login` endpoint. `req` is the request object, `res` is the response object, and `next` is a function to pass control to the next middleware.

2. `try {`

Starts a try block to catch and handle any errors that occur within the block.

3. `const { username, password } = req.body;`

Destructures the `username` and `password` from the request body. This is where the user submits their credentials.

4. `if (!username || !password) {`

Checks if either `username` or `password` is not provided.

5. `throw new ExpressError("Username and password required", 400);`

If either `username` or `password` is missing, it throws a custom error (ExpressError) indicating that both fields are required, with a 400 status code for Bad Request.

6.

```
const results = await db.query(
      `SELECT username, password
       FROM users
       WHERE username = $1`,
      [username]);
```

Asynchronously executes a SQL query to select the `username` and `password` from the `users` table where the `username` matches the provided username. The `sql` statement uses a parameterized query to prevent SQL injection attacks. Keep in mind the actual value to replace $1 in the query, which is the username provided by the user.

7. `const user = results.rows[0];`

Retrieves the first row from the query results, which should contain the user's data if the username exists in the database.

8. `if (user) {`

Checks if the user object exists, meaning the query found a user with the provided username.

9. `if (await bcrypt.compare(password, user.password)) {`

Asynchronously compares the provided password with the hashed password stored in the database using bcrypt.the `compare()` function returns a promise that resolves to a boolean value indicating whether the passwords match.

10. `const token = jwt.sign({ username }, SECRET_KEY);`

If the password matches, it generates a JWT token signed with the `SECRET_KEY`, including the `username` in the payload. The token is then sent back to the client in the response.

11. `return res.json({ message: `Logged in!`, token })`

Responds with a JSON object containing a success message and the JWT token.

12. `throw new ExpressError("Invalid username/password", 400);`

If either the user does not exist or the password does not match, it throws a custom error indicating invalid username/password with a 400 status code.

13. `} catch (e) {`

Catches any errors that occurred within the try block.

14.  `return next(e);`

Passes the error to the next error handling middleware in Express.

