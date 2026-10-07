import { JWT } from "google-auth-library";

/**
 * The parts of a service account's downloaded JSON key this needs — pass
 * JSON.parse() of the whole file; the other fields are ignored.
 */
export interface ServiceAccountKey {
  client_email: string;
  private_key: string;
}

export interface GoogleGroupCheckerOptions {
  /**
   * A service account that has been assigned the "Groups Reader" admin role
   * in the Workspace Admin console (Account → Admin roles → Groups Reader →
   * Assign service accounts). That role assignment is what lets it call the
   * Admin SDK as itself — no domain-wide delegation, no impersonating an
   * admin user.
   */
  serviceAccountKey: ServiceAccountKey;
}

export interface GoogleGroupChecker {
  /**
   * Whether email is a member of the group, directly or through a nested
   * group. Throws (rather than returning false) when Google can't answer —
   * a missing role, a mistyped group, an API outage — so a misconfiguration
   * surfaces as an error instead of silently locking everyone out.
   */
  isMember(email: string, groupEmail: string): Promise<boolean>;
}

const SCOPE = "https://www.googleapis.com/auth/admin.directory.group.member.readonly";

/**
 * Builds a Workspace group-membership check, for use inside isAllowed when
 * access should follow Google Group membership rather than just the domain:
 *
 *   const groups = googleGroupChecker({ serviceAccountKey });
 *   isAllowed: (profile) => groups.isMember(profile.email, "sitemap_access@kuutra.com")
 *
 * Backed by the Admin SDK Directory API's members.hasMember, which also
 * counts nested-group membership (as long as user and group are in the same
 * domain). Membership is only checked at login — the resulting session
 * stays valid for sessionTtlSeconds even if the user is removed from the
 * group in the meantime.
 */
export function googleGroupChecker(opts: GoogleGroupCheckerOptions): GoogleGroupChecker {
  const client = new JWT({
    email: opts.serviceAccountKey.client_email,
    key: opts.serviceAccountKey.private_key,
    scopes: [SCOPE],
  });

  return {
    async isMember(email, groupEmail) {
      const url =
        "https://admin.googleapis.com/admin/directory/v1/groups/" +
        `${encodeURIComponent(groupEmail)}/hasMember/${encodeURIComponent(email)}`;
      const res = await client.request<{ isMember?: boolean }>({ url });
      return res.data.isMember === true;
    },
  };
}
