const aclJson = require('./acl.json')

module.exports = (req, res, next) => {
  let roles = ['*'] // everyone always has the "*" (all) role

  if(req.session.user){
    roles = [...roles, ...req.session.user.roles] // pick roles from session uses
  } else {
    roles.push('anonymous') // add the non-authenticated role
  }

  // remove last '/' from request path
  let requestPath = req.path.endsWith('/') ? req.path.replace(/\/$/, "").toLowerCase() : req.path.toLowerCase()

  let controlList = Object.entries(aclJson).filter(([url, method]) => {
    url = url.toLowerCase()
    url.endsWith('/') && (url = url.replace(/\/$/, ""))

    // handle matching url including wildcard path endings
    if(url.includes('*')) {
      return requestPath.startsWith(url.split('*')[0])
    } else {
      return url == requestPath
    }
  })

  // Helper-function to remove code-duplication..
  const hasRole = (permission) => {
    if (!permission) { return false; }
    for (let role of roles) {
      if (permission.includes(role)) {
        return true;
      }
    }
  }
  
  // find ACL paths that matches roles
  controlList = controlList.filter(([url, permissions]) => {
    return hasRole(permissions['ALL']) || hasRole(permissions[req.method])
  });

  // pass!
  if (Object.keys(controlList).length > 0) {
    next();
  } else { 
    // reject! (we are not allowed here)
    res.status(403).send('Forbidden')
  }
}