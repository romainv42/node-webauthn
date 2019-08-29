/**
 * 
 */
export class CredCreateUserInformation {
  id: string;
  name: string;
  displayName: string;
  /**
   *
   */
  constructor(id: string, name: string, displayName: string) {
    this.id = id
    this.name = name
    this.displayName = displayName
  }
}
