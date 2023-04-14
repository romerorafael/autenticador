import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private baseUrl: string = "https://localhost:7293/api/User/";

  constructor( private http : HttpClient, private router: Router) { }

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
}
