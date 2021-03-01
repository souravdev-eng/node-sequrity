const { promisify } = require('util');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/email');
const User = require('../models/userSchema');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

const signInToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRS_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  // Cookie options
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKI_EXPIRS_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  // jwt token
  const token = signInToken(user._id);

  //*Cookie respoce[type of the cookie, send the token, set the cookie options]
  res.cookie('jwt', token, cookieOptions);

  // Remove the password from the output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'Success',
    token,
    data: {
      user
    }
  });
};

exports.signUp = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConforim: req.body.passwordConforim,
    passwordChangedAt: req.body.passwordChangedAt,
    role: req.body.role
  });
  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Cheack if there is a user and password
  if (!email || !password) {
    return next(new AppError('Please provaide a valid email or password', 400));
  }
  // 2) Cheack if user exsit and password is correct
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }
  // 3) If everything is fine, send the token
  const token = signInToken(user._id);
  res.status(200).json({
    status: 'Success',
    token
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1)  Getting token and Check of it's there.
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in again.', 401)
    );
  }
  // 2) Verification token.

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Cheack if user still exsist.

  const newUser = await User.findById(decoded.id);
  if (!newUser) {
    return next(new AppError('There is no user bellow this token', 401));
  }
  // 4) Cheack if user changed password after the token is issued.
  if (newUser.changePasswordAfter(decoded.iat)) {
    return next(
      new AppError('User is recently changed password! Please login again', 401)
    );
  }
  req.user = newUser;
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You dont have to permission to access this route ', 403)
      );
    }
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user baced on the email address
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email ', 404));
  }
  // 2) Ganaret the random token
  const resateToken = user.changePasswordRestToken();
  await user.save({ validateBeforeSave: false });
  // 3) Send it to user's email
  const restURL = `${req.protocol}://${req.get(
    'host'
  )}/api/users/restPassword/${resateToken}`;

  const message = `Forgot your password? Submit a PATCH request with the new password and conformipassword to :${restURL}`;

  try {
    await sendEmail({
      email: user.email,
      subject: `Your password restToken will expires in (10 mins)`,
      message
    });
    res.status(200).json({
      status: 'Successfull',
      message: 'Token is successfully send.'
    });
  } catch (error) {
    user.passwordRestToken = undefined;
    user.passwordRestTokenExpires = undefined;
    user.save({ validateBeforeSave: false });
    return next(new AppError('There was an error sending this email', 500));
  }
});

exports.resatePassword = catchAsync(async (req, res, next) => {
  // 1) Get the user baced on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');
  const user = await User.findOne({
    passwordRestToken: hashedToken,
    passwordRestTokenExpires: { $gt: Date.now() }
  });
  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError(`Token is invalid or expired`, 400));
  }
  user.password = req.body.password;
  user.passwordConforim = req.body.passwordConforim;
  user.passwordRestToken = undefined;
  user.passwordRestTokenExpires = undefined;
  await user.save();
  // 3) Update changedPasswordAt property for the user
  // 4) Log the user in, send JWT
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get the user from collections
  const user = await User.findById(req.user.id).select('+password');
  // 2) Cheack if the POSTed current password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your current password is incorrect', 401));
  }

  // 3) Update the password
  user.password = req.body.password;
  user.passwordConforim = req.body.passwordConforim;
  await user.save();
  // 4) Send JWT
  createSendToken(user, 200, res);
});
