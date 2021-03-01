const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'A user must have a name'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'A user must have a email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  photo: String,
  role: {
    type: String,
    enum: ['user', 'admin', 'lead-guide', 'guide'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'A user must have a password'],
    minLength: 8,
    select: false
  },
  passwordConforim: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function(el) {
        return el === this.password;
      },
      messages: 'Password are not the same'
    }
  },
  passwordChangedAt: Date,
  passwordRestToken: String,
  passwordRestTokenExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false
  }
});

//* Encrypt our user password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password') || !this.isNew) return next();

  //* Hasing and salting password
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConforim = undefined;
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.pre(/^find/, function(next) {
  this.find({ active: true });
  next();
});

userSchema.methods.correctPassword = async function(
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changePasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changeTimeStamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changeTimeStamp;
  }
  return false;
};

userSchema.methods.changePasswordRestToken = function() {
  const restToken = crypto.randomBytes(32).toString('hex');
  this.passwordRestToken = crypto
    .createHash('sha256')
    .update(restToken)
    .digest('hex');

  this.passwordRestTokenExpires = Date.now() + 10 * 60 * 1000;
  return restToken;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
