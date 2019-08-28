enum AuthenticatorAttachment {
  PLATFORM = "platform",
  CROSS_PLATFORM = "cross-platform"
}

enum ResidentKeyRequirement {
  DISCOURAGED = "discouraged",
  PREFERRED = "preferred",
  REQUIRED = "required"
}

enum UserVerificationRequirement {
  REQUIRED = "required",
  PREFERRED = "preferred",
  DISCOURAGED = "discouraged"
}

class AuthenticatorSelectionCriteria {
  authenticatorAttachment: AuthenticatorAttachment = AuthenticatorAttachment.CROSS_PLATFORM
  residentKey: ResidentKeyRequirement = ResidentKeyRequirement.REQUIRED
  userVerification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED
}

export {
  AuthenticatorAttachment,
  ResidentKeyRequirement,
  UserVerificationRequirement,
  AuthenticatorSelectionCriteria,
}
