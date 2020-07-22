const checkAuth = function(req, res, next){
    if (!req.session.user_id) {
      console.log('Not allowed');
      res.redirect('/');
    } else {
      console.log('Allowed');
      next();
    }
}

const checkTempPWD = function(req, res, next){
  if (!req.session.temp_pwd){
    console.log('User has not requested temporary password');
    res.redirect('/');
  } else {
    console.log('User has requested temporary password');
    next();
  }
}

module.exports = {
    checkAuth : checkAuth,
    checkTempPWD : checkTempPWD
};
