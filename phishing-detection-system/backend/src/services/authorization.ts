export type AccessRole = 'USER' | 'ADMIN'

export function canReadScan(actorId: string, actorRole: AccessRole, ownerId: string | null): boolean {
  return actorRole === 'ADMIN' || ownerId === actorId
}

export function canDeleteScan(actorId: string, ownerId: string | null): boolean {
  return ownerId === actorId
}
