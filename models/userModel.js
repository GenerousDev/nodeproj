const mongoose = require("mongoose");
const Joi = require("joi");

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Please provide an Email!"],
    unique: [true, "Email Exist"],
  },
  name: {
    type: String,
    min: 3,
    max: 255,
    required: true,
  },
  password: {
    type: String,
    required: [true, "Please provide a password!"],
    unique: false,
  },
  verified: {
    type: Boolean,
    default: false,
  },
});

const User = mongoose.model.users || mongoose.model("users", UserSchema);

const validate = (users) => {
  const schema = Joi.object({
    name: Joi.string().min(3).max(255).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(3).max(15).required(),
  });
  return schema.validate(users);
};

module.exports = {
  User,
  validate,
};
