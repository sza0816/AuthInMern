// this file is for registering a new user

const router = require("express").Router();
const { User, validate } = require("../models/user");
const bcrypt = require("bcrypt");

// take token model as variable token
const token = require("../models/token");
// take sendEmail function as variable sendEmail
const sendEmail = require("../utils/sendEmail");
// import crypto module for performing encryption and hashing operations
const crypto = require("crypto");

router.post("/", async (req, res) => {
	try {
		// check if request body is valid
		const { error } = validate(req.body);
		if (error)
			return res.status(400).send({ message: error.details[0].message });

		// check if user already exists
		let user = await User.findOne({ email: req.body.email });
		if (user)
			return res
				.status(409)
				.send({ message: "User with given email already Exist!" });

		// encrype password
		const salt = await bcrypt.genSalt(Number(process.env.SALT));
		const hashPassword = await bcrypt.hash(req.body.password, salt);

		// create new user
		user = await new User({ ...req.body, password: hashPassword }).save();

		// generate a new token variable
		const token = await new TokenExpiredError({
			userId: user._id, 
			token: crypto.randomBytes(32).toString("hex"), // random token string
		}).save();

		// generate link and send email
		const url = `${process.env.BASE_URL}users/${user._id}/verify/${token.token}`;
		await sendEmail(user.email, "Verify Email", url);


		res.status(201).send({ message: "User created successfully. An email is sent to your account, please verify" });
	} catch (error) {
		res.status(500).send({ message: "Internal Server Error" });
	}
});

module.exports = router;
