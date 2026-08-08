import BSVCore
import BSVWallet

public enum IdentityParser {
    public static func parse(
        _ identity: WalletIdentityCertificate,
        limits: IdentityLimits
    ) throws -> DisplayableIdentity {
        let knownType = KnownIdentityType(certificateType: identity.certificate.type)
        let fields = identity.decryptedFields
        let certifierName = identity.certifierInfo.name
        var name = ""
        var avatarURL = ""
        var badgeLabel = ""
        var badgeIconURL = ""
        var badgeClickURL = ""

        switch knownType {
        case .x:
            name = field("userName", in: fields)
            avatarURL = field("profilePhoto", in: fields)
            badgeLabel = try joined(
                prefix: "X account certified by ", value: certifierName, limits: limits
            )
            badgeIconURL = identity.certifierInfo.iconURL
            badgeClickURL = "https://socialcert.net"
        case .discord:
            name = field("userName", in: fields)
            avatarURL = field("profilePhoto", in: fields)
            badgeLabel = try joined(
                prefix: "Discord account certified by ", value: certifierName, limits: limits
            )
            badgeIconURL = identity.certifierInfo.iconURL
            badgeClickURL = "https://socialcert.net"
        case .email:
            name = field("email", in: fields)
            avatarURL = "XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu"
            badgeLabel = try joined(
                prefix: "Email certified by ", value: certifierName, limits: limits
            )
            badgeIconURL = identity.certifierInfo.iconURL
            badgeClickURL = "https://socialcert.net"
        case .phone:
            name = field("phoneNumber", in: fields)
            avatarURL = "XUTLxtX3ELNUwRhLwL7kWNGbdnFM8WG2eSLv84J7654oH8HaJWrU"
            badgeLabel = try joined(
                prefix: "Phone certified by ", value: certifierName, limits: limits
            )
            badgeIconURL = identity.certifierInfo.iconURL
            badgeClickURL = "https://socialcert.net"
        case .identiCert:
            name = try joined(
                prefix: field("firstName", in: fields),
                separator: " ",
                value: field("lastName", in: fields),
                limits: limits
            )
            avatarURL = field("profilePhoto", in: fields)
            badgeLabel = try joined(
                prefix: "Government ID certified by ", value: certifierName, limits: limits
            )
            badgeIconURL = identity.certifierInfo.iconURL
            badgeClickURL = "https://identicert.me"
        case .registrant:
            name = field("name", in: fields)
            avatarURL = field("icon", in: fields)
            badgeLabel = try joined(
                prefix: "Entity certified by ", value: certifierName, limits: limits
            )
            badgeIconURL = identity.certifierInfo.iconURL
            badgeClickURL = "https://projectbabbage.com/docs/registrant"
        case .cool:
            name = field("cool", in: fields) == "true" ? "Cool Person!" : "Not cool!"
        case .anyone:
            name = "Anyone"
            avatarURL = "XUT4bpQ6cpBaXi1oMzZsXfpkWGbtp2JTUYAoN7PzhStFJ6wLfoeR"
            badgeLabel = "Represents the ability for anyone to access this information."
            badgeIconURL = "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG"
            badgeClickURL = "https://projectbabbage.com/docs/anyone-identity"
        case .self:
            name = "You"
            avatarURL = "XUT9jHGk2qace148jeCX5rDsMftkSGYKmigLwU2PLLBc7Hm63VYR"
            badgeLabel = "Represents your ability to access this information."
            badgeIconURL = "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG"
            badgeClickURL = "https://projectbabbage.com/docs/self-identity"
        case nil:
            return try DisplayableIdentity.unknown(
                avatarURL: field("profilePhoto", in: fields),
                limits: limits
            )
        }

        let identityKey = Hex.encode(identity.certificate.subject.compressedBytes)
        let abbreviatedKey = String(identityKey.prefix(10)) + "..."
        return try DisplayableIdentity(
            name: name,
            avatarURL: avatarURL,
            abbreviatedKey: abbreviatedKey,
            identityKey: identityKey,
            badgeIconURL: badgeIconURL,
            badgeLabel: badgeLabel,
            badgeClickURL: badgeClickURL,
            limits: limits
        )
    }

    private static func field(
        _ name: String,
        in values: [CertificateFieldName: String]
    ) -> String {
        values.first(where: { $0.key.value == name })?.value ?? ""
    }

    private static func joined(
        prefix: String,
        separator: String = "",
        value: String,
        limits: IdentityLimits
    ) throws -> String {
        let (first, overflow1) = prefix.utf8.count.addingReportingOverflow(separator.utf8.count)
        let (count, overflow2) = first.addingReportingOverflow(value.utf8.count)
        guard !overflow1, !overflow2 else { throw IdentityError.sizeOverflow }
        guard count <= limits.maximumDisplayTextUTF8ByteCount else {
            throw IdentityError.displayTextTooLarge(
                actual: count,
                maximum: limits.maximumDisplayTextUTF8ByteCount
            )
        }
        return prefix + separator + value
    }
}
