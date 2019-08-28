/**
 * 
 */
export class CredCreateUserInformation {
  id: string;
  username: string;
  displayName: string;
  /**
   *
   */
  constructor(id: string, username: string, displayName: string) {
    this.id = id
    this.username = username
    this.displayName = displayName
  }
}
