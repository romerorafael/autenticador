import { Component, OnInit} from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import ValidateForm from '../../helpers/validatesForm'
import { AuthService } from 'src/app/services/auth.service';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup'

@Component({
  selector: 'app-signup',
  templateUrl: './signup.component.html',
  styleUrls: ['./signup.component.css']
})
export class SignupComponent implements OnInit{

  constructor(
    private fb:FormBuilder, 
    private auth: AuthService, 
    private router:Router,
    private toast:NgToastService
  ){}

  type: string= "password";
  eyeIcon: string = "fa-eye-slash";
  isText: boolean = false;
  signUpForm!: FormGroup;

  ngOnInit(): void {
    this.signUpForm = this.fb.group({
      firstName:['', Validators.required],
      lastName:['',Validators.required],
      email:['',Validators.required],
      username:['',Validators.required],
      password:['',Validators.required]
    });
  }

  hideShowPass(){
    this.isText = !this.isText;
    this.isText ?  this.eyeIcon = "fa-eye" : this.eyeIcon = "fa-eye-slash";
    this.isText ? this.type = "text" : this.type = "password";
  }

  onSignUp(){
    if(this.signUpForm.valid){
      this.auth.signUp(this.signUpForm.value).subscribe({
        next:(res=>{
          this.toast.success({detail:"SUCESSO",summary:res.message, duration:5000});
          this.signUpForm.reset;
          this.router.navigate(["login"]);
        }),
        error:(err=>{
          this.toast.error({detail:"ERRO",summary:err.error.message, duration:5000});
        })
      })
    }else{
      ValidateForm.validateAllFields(this.signUpForm);
    }
  }

}
