/** Mirrors internal/domain/target.Target exactly. A "target" is this
 * backend's project/workspace concept — the frontend's project selector
 * (spec §13/§54) is scoped by TargetID exactly the way every backend
 * service is. */

export type TargetType =
  | "DOMAIN"
  | "HOST"
  | "IP"
  | "CIDR"
  | "URL"
  | "REPOSITORY"
  | "CLOUD_ACCOUNT";

export type AuthorizationStatus =
  | "UNVERIFIED"
  | "AUTHORIZED"
  | "EXPIRED"
  | "REVOKED";

export interface Target {
  id: string;
  name: string;
  type: TargetType;
  value: string;
  description: string;
  authorizationStatus: AuthorizationStatus;
  createdAt: string;
  updatedAt: string;
}
