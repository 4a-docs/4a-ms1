<?php

namespace App\Observers;

use App\Models\User;

class UserObserver
{

    public function creating(User $user)
    {
        if (! \App::runningInConsole()) {

            if ( auth()->user() && auth()->user()->roles[0]->name === 'admin' ) {
                $user->admin_id = auth()->user()->id;
            }else{
                $user->admin_id = null;
            }

        }
    }

}
