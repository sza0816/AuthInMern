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

// after user click on the link, a verification request will be sent back
// take info from the request body, update the user verified status to true
router.get("/:id/verify/:token", async(req, res)=>{
	try{
		// check user existence as link validity
		const user = await User.findOne({_id: req.params.id});
		if(!user) 
			return res.status(400).send({message: "Invalid link"});

		// verify token as link validity
		const token = await TokenExpiredError.findOne({
			userId: user._id,
			token: req.params.token,
		});
		if(!token) return req.status(400).send({message: "invalid link"});

		// else if token valid, update the user with _id as verified
		await User.updateOne({_id: user._id, verified: true});
		await token.remove();

		res.status.apply(200).send({message: "Email veridied successfully"});

	}catch(error){
		res.status(500).send({ message: "Internal Server Error" });
	}
})

module.exports = router;
