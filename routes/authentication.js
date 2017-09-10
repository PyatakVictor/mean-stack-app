const User = require('../models/user');

module.exports = (router) => {

    router.post('/register', (req, res) => {
        if (!req.body.email) {
            res.json({
                success: false,
                message: 'You have to fill email input'
            });
        } else {
            if (!req.body.username) {
                res.json({
                    success: false,
                    message: 'You have to fill username input'
                });

            } else {

                if (!req.body.password) {
                    res.json({
                        success: false,
                        message: 'You have to fill password input'
                    });
                } else {

                    let user = new User({
                        email: req.body.email.toLowerCase(),
                        username: req.body.username.toLowerCase(),
                        password: req.body.password
                    });

                    user.save((err) => {
                        if (err) {
                            if (err.code == 11000) {
                                res.json({
                                    success: false,
                                    message: 'Username or email already exists'
                                });
                            } else {
                                if (err.errors) {
                                    if (err.errors.email) {
                                        res.json({
                                            success: false,
                                            message: err.errors.email.message
                                        });
                                    }else{
                                        if(err.errors.username){
                                            res.json({
                                                success: false,
                                                message: err.errors.username.message
                                            });
                                        }else{
                                            if(err.errors.password){
                                                res.json({
                                                    success:false,
                                                    message:err.errors.password.message
                                                });
                                            }else{
                                                res.json({success:false, message:err});
                                            }
                                        }
                                    }
                                } else {

                                    res.json({
                                        success: false,
                                        message: 'Could not save user',
                                        err
                                    });
                                }

                            }

                        } else {
                            res.json({
                                success: true,
                                message: 'You are registered!'
                            });
                        }

                    });

                }


            }
        }
    });

    return router;
}