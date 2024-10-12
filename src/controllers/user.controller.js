import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
    try {

        const user = await User.findById(userId);
        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave : true });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh token");
    }
}

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation
    // check if user already exists : username, email
    // check for images, check for avatar
    // upload files to cloudinary
    // create user object - create entry in db
    // remove password and refresh token from response
    // check for user creation
    // return response

    const {fullName, email, username, password} = req.body;
    //console.log("Email : ",email,"\nPassword (Unencrypted) : ",password);

    // if(fullName === ""){
    //     throw new ApiError(400, "Fullname is required");
    // }

    if(
        [fullName, email, username, password].some(
            (field) => field?.trim()===""
        )
    ){
        throw new ApiError(400, "All fields are required.");
    }

    const existingUser = await User.findOne({
        $or: [{ email }, { username }]
    })

    if(existingUser){
        throw new ApiError(409, "User with Username or Email already exists")
    }

    //const avatarLocalPath = req.files?.avatar[0]?.path; //since we already used multer 
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let avatarLocalPath;
    if(req.files && Array.isArray(req.files.avatar) && req.files.avatar.length > 0){
        avatarLocalPath = req.files.avatar[0].path;
    }

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required.");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
        throw new ApiError(400, "Avatar file not uploaded on cloudinary.");
    }

    const user = await User.create({
        fullName,
        avatar : avatar.url,
        coverImage : coverImage?.url || "",
        email,
        password,
        username : username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering the user");
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
})

const loginUser = asyncHandler(async (req,res) => {
    // get data from body
    // username or email
    // find the user
    // check password
    // generate access and refresh token
    // send cookies

    const {email, username, password} = req.body;

    if(!(!email || !username)){
        throw new ApiError(400, "username or password is required");
    }

    const user = await User.findOne({
        $or : [{email},{username}]
    })

    if(!user){
        throw new ApiError(404, "User does not exist");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid User Credentials");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly : true,
        secure : true
    }

    return res.
    status(200).
    cookie("accessToken", accessToken, options).
    cookie("refreshToken", refreshToken, options).
    json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User Logged in successfully"
        )
    )
})

const logoutUser = asyncHandler(async (req, res) => {
    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set : {
                refreshToken : undefined
            },
        },
        {
            new : true //this will make sure that it returns updated value
        }
    );

    const options = {
        httpOnly : true,
        secure : true
    }

    return res.
    status(200).
    clearCookie("accessToken", options).
    clearCookie("refreshToken", options).
    json(
        new ApiResponse(200, {}, "User Logged Out successfully")
    )
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken;
    
        if(!incomingRefreshToken){
            throw new ApiError(401, "Unauthorized Request");
        }
    
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    
        const user = await User.findById(decodedToken?._id);
    
        if(!user){
            throw new ApiError(401, "Invalid refresh Token");
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh Token is Expired");
        }
    
        const options = {
            httpOnly : true,
            secure : true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshToken(user._id)
    
        return res.
        status(200).
        cookie("accessToken", accessToken, options).
        cookie("refreshToken", newRefreshToken, options).
        json(
            new ApiResponse(
                200,
                {
                    accessToken, refreshToken : newRefreshToken
                },
                "Access Token refreshed successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Refresh Token")
    }
})

const changeCurrentUserPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user?._id);

    const isPasswordCorrect = user.isPasswordCorrect(oldPassword);

    if(!isPasswordCorrect){
        throw new ApiError(401, "Invalid Old Password");
    }

    user.password = newPassword;

    await user.save({validateBeforeSave : false});

    return res.
    status(200).
    json(
        new ApiResponse(200, {}, "Password Changed Successfully")
    )
})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
    .status(200)
    .json(200, req.user , "Current User Fetched successfully");
})

const updateAccountDetails = asyncHandler(async (req, res) => {
    const {fullName, email} = req.body;

    if(!fullName || !email){
        throw new ApiError(400, "All fields are required");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set : {
                fullName,
                email
            }
        },
        {
            new : true
        }
    ).select("-password -refreshToken");

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Fullname and Email updated successfully")
    )
})

const updateUserAvatar = asyncHandler(async (req, res) => {
    let newAvatarLocalPath;
    if (req.file?.path) {
        newAvatarLocalPath = req.file.path;
    }

    if (!newAvatarLocalPath) {
        throw new ApiError(400, "New Avatar file is required.");
    }

    const newAvatar = await uploadOnCloudinary(newAvatarLocalPath);

    if (!newAvatar?.url) {
        throw new ApiError(400, "New Avatar file not uploaded on cloudinary.");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        { $set: { avatar: newAvatar.url } },
        { new: true }
    ).select("-password -refreshToken");

    if (!user) {
        throw new ApiError(404, "User not found.");
    }

    return res.status(200).json(
        new ApiResponse(200, user, "New User Avatar updated successfully")
    );
});

const updateCoverImage = asyncHandler(async (req, res) => {
    let newCoverImagePath;
    if (req.file?.path) {
        newCoverImagePath = req.file.path;
    }

    if (!newCoverImagePath) {
        throw new ApiError(400, "New Cover Image file is required.");
    }

    const newCoverImage = await uploadOnCloudinary(newCoverImagePath);

    if (!newCoverImage?.url) {
        throw new ApiError(400, "New Cover Image file not uploaded on cloudinary.");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        { $set: { coverImage: newCoverImage.url } },
        { new: true }
    ).select("-password -refreshToken");

    if (!user) {
        throw new ApiError(404, "User not found.");
    }

    return res.status(200).json(
        new ApiResponse(200, user, "New Cover Image updated successfully")
    );
});


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentUserPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserAvatar,
    updateCoverImage
};