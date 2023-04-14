import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'
import { Router } from '@angular/router';
import { JwtHelperService }  from '@auth0/angular-jwt';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private baseUrl: string = "https://localhost:7293/api/User/";
  private userPayload: any;
  constructor( private http : HttpClient, private router: Router) {
    this.userPayload = this.decodeToken();
   }

  signUp( userObj:any){
    return this.http.post<any>(`${this.baseUrl}register`, userObj);
  }

  login(userObj:any){
    return this.http.post<any>(`${this.baseUrl}authenticate`, userObj);
  }

  storeToken(tokenValue : string){
    localStorage.setItem('token', tokenValue)
  }

  getToken() : string|null{
    return localStorage.getItem('token');
  }

  logout(){
    localStorage.removeItem('token');
    this.router.navigate(['login']);
  }

  isLoggedIn() : boolean{
    return !!localStorage.getItem('token')
  }

  decodeToken(){
    const jwtHelper = new JwtHelperService();
    const token = this.getToken()!;
    return jwtHelper.decodeToken(token);
  }

  getFullNameFromToken(){
    if(this.userPayload){
      console.log(this.userPayload)
      return this.userPayload.unique_name;
    }
  }

  getRoleFromToken(){
    if(this.userPayload){
      return this.userPayload.role;
    }
  }
}
