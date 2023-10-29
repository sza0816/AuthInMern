const router = require("express").Router();
const { User } = require("../models/user");
const bcrypt = require("bcrypt");
const Joi = require("joi");

// take token model as variable token
const Token = require("../models/token");
// take sendEmail function as variable sendEmail
const sendEmail = require("../utils/sendEmail");
// import crypto module for performing encryption and hashing operations
const crypto = require("crypto");

router.post("/", async (req, res) => {
	try {
		const { error } = validate(req.body);
		if (error)
			return res.status(400).send({ message: error.details[0].message });

		const user = await User.findOne({ email: req.body.email });
		if (!user)
			return res.status(401).send({ message: "Invalid Email or Password" });

		const validPassword = await bcrypt.compare(
			req.body.password,
			user.password
		);
		if (!validPassword)
			return res.status(401).send({ message: "Invalid Email or Password" });

		if(!user.verified){
			// find a token corresponds with user id
			// let token = await Token.findOne({userId: user._id});
			// if token not exist
			// if(!token){
				// regenerate a new token variable
				const token = await new TokenExpiredError({
				userId: user._id, 
				token: crypto.randomBytes(32).toString("hex"), // random token string
				}).save();

				// regenerate link and send email
				const url = `${process.env.BASE_URL}users/${user._id}/verify/${Token.token}`;
				await sendEmail(user.email, "Verify Email", url);
			// }
			// method1: if token exist but not verified, remind user of a previous email by response
			// **method2**: no matter whether token exists or not, resend an email, respond
			return res.status(400).send({message: "An email is sent to your account, please check."});
		}

		const token = user.generateAuthToken();
		res.status(200).send({ data: token, message: "logged in successfully" });
	} catch (error) {
		res.status(500).send({ message: "Internal Server Error" });
	}
});

const validate = (data) => {
	const schema = Joi.object({
		email: Joi.string().email().required().label("Email"),
		password: Joi.string().required().label("Password"),
	});
	return schema.validate(data);
};

module.exports = router;
