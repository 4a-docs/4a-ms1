<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        User::create([
            'name' => 'Anderson',
            'last_name' => 'Daza',
            'phone' => '3102558563',
            'eps' => 'capresoca',
            'identification' => '1000522314',
            'birthdate' => '1996-12-24',
            'email' => 'anderson@g.com',
            'email_verified_at' => now(),
            'password' => bcrypt('12345678') 
        ])->assignRole(['admin']);

        User::create([
            'name' => 'Laura',
            'last_name' => 'Patarroyo',
            'phone' => '3186358563',
            'eps' => 'Nueva eps',
            'identification' => '1056922314',
            'birthdate' => '2000-10-04',
            'email' => 'laura@g.com',
            'email_verified_at' => now(),
            'password' => bcrypt('12345678') 
        ])->assignRole(['admin']);

        User::create([
            'name' => 'Santiago',
            'last_name' => 'Rodriguez',
            'phone' => '311598563',
            'eps' => 'capresoca',
            'identification' => '1009632314',
            'birthdate' => '1999-05-24',
            'email' => 'santiago@g.com',
            'email_verified_at' => now(),
            'password' => bcrypt('12345678') 
        ])->assignRole(['admin']);

        User::create([
            'name' => 'María',
            'last_name' => 'Torres',
            'phone' => '311547563',
            'eps' => 'Nueva eps',
            'identification' => '1008612314',
            'birthdate' => '1999-06-11',
            'email' => 'maria@g.com',
            'email_verified_at' => now(),
            'password' => bcrypt('12345678') 
        ])->assignRole(['patient']);

        User::create([
            'name' => 'Julian',
            'last_name' => 'Arias',
            'phone' => '310237563',
            'eps' => 'capresoca',
            'identification' => '1008942314',
            'birthdate' => '1999-08-23',
            'email' => 'julian@g.com',
            'email_verified_at' => now(),
            'password' => bcrypt('12345678') 
        ])->assignRole(['patient']);
    }
}
