import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'
import { Router } from '@angular/router';
import { JwtHelperService }  from '@auth0/angular-jwt';
<<<<<<< HEAD
import { TokenApiModel } from '../models/token-api.model';
=======
>>>>>>> 64135db01914d446fc01ba05e13a01378e95dbfc

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

  storeRefreshToken(tokenValue:string){
    localStorage.setItem('refreshToken', tokenValue)
  }

  getToken() : string|null{
    return localStorage.getItem('token');
  }

  getRefreshToken() : string|null{
    return localStorage.getItem('refreshToken');
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
      return this.userPayload.unique_name;
    }
  }

  getRoleFromToken(){
    if(this.userPayload){
      return this.userPayload.role;
    }
  }

  renewToken(tokenApi:TokenApiModel){
    return this.http.post<any>(`${this.baseUrl}refresh`, tokenApi);
  }
}
