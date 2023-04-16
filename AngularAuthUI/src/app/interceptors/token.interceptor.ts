import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { Observable, catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { NgToastService } from 'ng-angular-popup';
import { Router } from '@angular/router';
import { TokenApiModel } from '../models/token-api.model';

@Injectable()
export class TokenInterceptor implements HttpInterceptor {

  constructor(private auth: AuthService, private toast: NgToastService, private router: Router) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<any> {
    const myToken = this.auth.getToken();

    if(myToken){
      request = request.clone({
        setHeaders: {Authorization: `Bearer ${myToken}`}
      })
    }

    return next.handle(request).pipe(
      catchError((err:any) =>{
        if(err instanceof HttpErrorResponse){
          if(err.status === 401){
            return this.handleUnAuthorized(request, next);
          }
        }
        return throwError(()=> new Error("Erro desconhecido"));
      }));
  }

  handleUnAuthorized( req: HttpRequest<any>, next: HttpHandler){
    const accessToken = this.auth.getToken()!;
    const refresToken = this.auth.getRefreshToken()!;

    const tokenApiModel = new TokenApiModel();
    tokenApiModel.accessToken = accessToken;
    tokenApiModel.refreshToken = refresToken;

    return this.auth.renewToken(tokenApiModel).pipe(
      switchMap((data: TokenApiModel) : any => {
        this.auth.storeRefreshToken(data.refreshToken);
        this.auth.storeToken(data.accessToken);
        req = req.clone({
          setHeaders: {Authorization: `Bearer: ${data.accessToken}`}
        })
        return next.handle(req);
      }),
      catchError((err)=>{
        return throwError(()=>{
          this.toast.warning({detail:"Aviso", summary:"Token expirado, porfavor refaça o login"});
          this.router.navigate(['login']);
        })
      })
    )
  }
}
