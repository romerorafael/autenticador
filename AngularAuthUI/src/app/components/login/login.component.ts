import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import ValidateForm from '../../helpers/validatesForm'
import { AuthService } from 'src/app/services/auth.service';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup'
import { UserStoreService } from 'src/app/services/user-store.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit{
  
  type: string= "password";
  eyeIcon: string = "fa-eye-slash";
  isText: boolean = false;
  loginForm!: FormGroup;
  resetPasswordEmail!: string;
  isValidEmail!: boolean ;

  constructor(
    private fb:FormBuilder, 
    private auth: AuthService, 
    private route:Router,
    private toast:NgToastService,
    private userStore: UserStoreService 
  ) {}

  ngOnInit(): void {
    this.loginForm = this.fb.group({
      username:['',Validators.required],
      password:['',Validators.required]
    });
  }

  hideShowPass(){
    this.isText = !this.isText;
    this.isText ?  this.eyeIcon = "fa-eye" : this.eyeIcon = "fa-eye-slash";
    this.isText ? this.type = "text" : this.type = "password";
  }

  onSubmit(){
    if(this.loginForm.valid){
      this.auth.login(this.loginForm.value).subscribe({
        next:(res)=>{
          this.loginForm.reset;
          this.auth.storeToken(res.accessToken);
          this.auth.storeRefreshToken(res.refresToken);
          const tokenPayload = this.auth.decodeToken();
          this.userStore.setFullNameFromStore(tokenPayload.unique_name);
          this.userStore.setRoleFoStore(tokenPayload.role);
          this.toast.success({detail:"SUCESSO",summary:res.message, duration:5000});
          this.route.navigate(['dashboard']);
        },
        error:(err)=>{
          this.toast.error({detail:"ERRO",summary:err.message, duration:5000});
        }
      })
    }else{
      ValidateForm.validateAllFields(this.loginForm);
    }
  }

  checkValidEmail(event:string){
    const value = event;
    const pattern = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
    this.isValidEmail = pattern.test(value);
    return this.isValidEmail; 
  }

  confimToSend(){
    if(this.checkValidEmail(this.resetPasswordEmail)){
      this.resetPasswordEmail = "";
      const buttonRef = document.getElementById('closeBtn');
      buttonRef?.click();
    }
  }
}
