import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import ValidateForm from '../../helpers/validatesForm'
import { AuthService } from 'src/app/services/auth.service';
import { Router } from '@angular/router';

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

  constructor(private fb:FormBuilder, private auth: AuthService, private route:Router) {}

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
          alert(res.message);
          this.loginForm.reset;
          this.route.navigate(['dashboard']);
        },
        error:(err)=>{
          alert(err.error.message)
        }
      })
    }else{
      ValidateForm.validateAllFields(this.loginForm);
    }
  }

}
