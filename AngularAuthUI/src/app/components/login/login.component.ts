import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import ValidateForm from '../../helpers/validatesForm'
import { AuthService } from 'src/app/services/auth.service';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup'

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit{
  
  type: string= "password";
  eyeIcon: string = "fa-eye-slash";
  isText: boolean = false;
  loginForm: FormGroup = this.fb.group({
    username:['',Validators.required],
    password:['',Validators.required]
  });

  constructor(
    private fb:FormBuilder, 
    private auth: AuthService, 
    private route:Router,
    private toast:NgToastService  
  ) {}

  ngOnInit(): void {
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
          this.auth.storeToken(res.token);
          this.toast.success({detail:"SUCESSO",summary:res.message, duration:5000});
          this.route.navigate(['dashboard']);
        },
        error:(err)=>{
          this.toast.error({detail:"ERRO",summary:err.error.message, duration:5000});
        }
      })
    }else{
      ValidateForm.validateAllFields(this.loginForm);
    }
  }

}
