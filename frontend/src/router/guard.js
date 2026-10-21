export function evaluateAuthGuard({
  toPath,
  requiresAuth,
  roles = [],
  isAuthenticated,
  token,
  needsPasswordChange,
  passwordChanged,
  userRole,
}) {
  const hasSession = Boolean(isAuthenticated || token)

  if (toPath === '/login') {
    if (hasSession && !needsPasswordChange) return '/dashboard'
    return true
  }

  if (toPath === '/change-password') {
    if (!hasSession && !needsPasswordChange) return '/login'
    return true
  }

  if (requiresAuth && !hasSession) return '/login'
  if (needsPasswordChange && !passwordChanged && toPath !== '/change-password') return '/change-password'
  if (toPath === '/forbidden') return true
  if (roles.length > 0 && !roles.includes(userRole)) return '/forbidden'

  return true
}
