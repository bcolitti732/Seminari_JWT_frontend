import { HttpEvent, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { Observable, catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from './auth.service';

export function jwtInterceptor(req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> {
  console.log("Dentro del interceptador");

  const token = localStorage.getItem('access_token');
  const router = inject(Router);
  const toastr = inject(ToastrService);
  const authService = inject(AuthService);

  if (token) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  return next(req).pipe(
    catchError((error) => {
      if (error.status === 401) {
        // Intentar refrescar el token si expira
        return authService.refreshToken().pipe(
          switchMap((response) => {
            const newToken = response.token;
            localStorage.setItem('access_token', newToken);

            // Reintentar la petició original amb el nou token
            req = req.clone({
              setHeaders: {
                Authorization: `Bearer ${newToken}`
              }
            });
            return next(req);
          }),
          catchError((refreshError) => {
            // Si el refresh falla, netejar el token i redirigir a login
            localStorage.removeItem('access_token');
            toastr.error(
              'Su sesión ha expirado. Por favor, inicie sesión nuevamente.',
              'Sesión Expirada',
              {
                timeOut: 3000,
                closeButton: true
              }
            );
            router.navigate(['/login']);
            return throwError(() => refreshError);
          })
        );
      }
      return throwError(() => error);
    })
  );
}