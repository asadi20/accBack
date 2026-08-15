<?php

namespace App\Http\Controllers\Api\RBAC;

use App\Http\Controllers\Controller;
use DB;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class RoleController extends Controller
{
    public function index()
    {
        // show all roles
        $roles = Role::all();
        return response()->json([
            'success' => true,
            'data' => $roles,
            'message' => 'all roles retrieved successfully.'
        ], 200);
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => [
                'required',
                'string',
                'max:255',
                Rule::unique('roles')->where(function ($query) use ($request) {
                    return $query->where('guard_name', $request->guard_name);
                }),
            ],
            'guard_name' => 'required|string'
        ]);

        $newRole = Role::create($validated);

        return response()->json([
            'success' => true,
            'data' => $newRole,
            'message' => 'New Role added to system.'
        ], 201);
    }

    public function getRolePermsByRoleId($id)
    {
        $rolePerms = Role::with('permissions')->find($id);
        $perms = Permission::all();

        $res = [
            'rolePerms' => $rolePerms,
            'perms' => $perms
        ];

        return response()->json([
            'message' => 'requested role with all related permissions are retrieved successfully.',
            'data' => $res,
            'errors' => null
        ], 200);
    }

    public function update(Request $request, $id)
    {
        $validated = $request->validate([
            'name' => 'required|string',
            'guard_name' => 'required|string',
            'permIds' => 'array',
            'permIds.*' => 'exists:permissions,id'
        ]);

        $role = DB::transaction(function () use ($validated, $id) {
            $role = Role::findOrFail($id);
            // 1. update Role with validated $request array
            $role->update([
                'name' => $validated['name'],
                'guard_name' => $validated['guard_name']
            ]);
            // 2.update permissions if exists.
            if (isset($validated['permIds'])) {
                $role->syncPermissions($validated['permIds']);
            }
            // 3.!! return update Model not a response
            return $role->load('permissions');
        });
        // 4.return a response
        return response()->json([
            'success' => true,
            'message' => 'role and related permissions updated successfully',
            'data' => $role
        ], 200);
    }
}
