const asyncHandler = (requestHandler) => { //We don't use async here as it will return the Promise itself
    return (req, res, next) => {
        Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err));
    }
}

export {asyncHandler};