/** Common settings for auth-api app. */

const DB_URI = (process.env.NODE_ENV === "test")
  ? "postgresql:///express_auth_test"
  : "postgresql:///express_auth";

const SECRET_KEY = process.env.SECRET_KEY || "fHt$TRcC%25HmE8gC'vD$!Ka%8sOt;~V,XItr+8t+)8;x}O/rSQgGyG7}o^c1')"

//Common values for BCRYPT_WORK_FACTOR range from 10 to 14 in many applications. A value of 12 is considered to be reasonably secure for most applications today, providing a good balance between security and performance. It's neither too low to be insecure nor too high to cause significant delays in normal authentication processes.

// Minimum: There's no absolute minimum, but values below 10 are generally considered too low for security purposes in current computing environments. Lower values mean faster computation, which could make it easier for attackers to perform brute-force attacks.

// Maximum: The maximum is not explicitly defined, as it depends on the application's tolerance for delay in password hashing and verification. However, values above 14-15 can lead to noticeable delays in user authentication, especially on servers with high traffic or limited computational resources.

const BCRYPT_WORK_FACTOR = 12;

module.exports = {
  DB_URI,
  SECRET_KEY,
  BCRYPT_WORK_FACTOR
};
