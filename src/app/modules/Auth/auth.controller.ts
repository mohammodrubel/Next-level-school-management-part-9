import httpStatus from 'http-status';
import config from '../../config';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { AuthServices } from './auth.service';

const loginUser = catchAsync(async (req, res) => {
  const result = await AuthServices.loginUser(req.body);
  const { refreshToken, accessToken, needsPasswordChange } = result;
  res.cookie('refreshToken', refreshToken, {
    secure: config.NODE_ENV === 'production',
    httpOnly: true,
  });

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User is logged in succesfully!',
    data: {
      accessToken,
      needsPasswordChange,
    },
  });
});

const changePassword = catchAsync(async (req, res) => {
  const { ...passwordData } = req.body;

  const result = await AuthServices.changePassword(req.user, passwordData);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password is updated succesfully!',
    data: result,
  });
});

const refreshToken = catchAsync(async (req, res) => {
  const { refreshToken } = req.cookies;
  const result = await AuthServices.refreshToken(refreshToken);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Access token is retrieved succesfully!',
    data: result,
  });
});

const forgatePassword = catchAsync(async(req,res)=>{
  const {id} = req.body
  const result = await AuthServices.forgatePasswordService(id)
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Reset Link is Genareate  succesfully!',
    data: result,
  });
})
const resetPassword = catchAsync(async(req,res)=>{
  const token = req.headers.authorization as string
  const result = await AuthServices.resetPasswordService(req.body,token)
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'password reset  succesfully!',
    data: result,
  });
})

export const AuthControllers = {
  loginUser,
  changePassword,
  refreshToken,
  forgatePassword,
  resetPassword
};
