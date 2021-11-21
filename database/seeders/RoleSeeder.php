<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class RoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $role1 = Role::create(['name' => 'admin',]);
        $role2 = Role::create(['name' => 'doctor']);
        $role3 = Role::create(['name' => 'patient']);

        Permission::create(['name' => 'admin.doctors.index'])->syncRoles([$role1]);
        Permission::create(['name' => 'admin.doctors.create'])->syncRoles([$role1]);
        Permission::create(['name' => 'admin.doctors.edit'])->syncRoles([$role1]);
        Permission::create(['name' => 'admin.doctors.destroy'])->syncRoles([$role1]);

        Permission::create(['name' => 'doctor.agendas.index'])->syncRoles([ $role2]);
        Permission::create(['name' => 'doctor.agendas.create'])->syncRoles([ $role2]);
        Permission::create(['name' => 'doctor.agendas.edit'])->syncRoles([ $role2]);
        Permission::create(['name' => 'doctor.agendas.destroy'])->syncRoles([$role2]);

        Permission::create(['name' => 'patient.appointments.index'])->syncRoles([ $role2]);
        Permission::create(['name' => 'patient.appointments.create'])->syncRoles([ $role2]);
        Permission::create(['name' => 'patient.appointments.edit'])->syncRoles([ $role2]);
        Permission::create(['name' => 'patient.appointments.destroy'])->syncRoles([$role2]);
    }
}
