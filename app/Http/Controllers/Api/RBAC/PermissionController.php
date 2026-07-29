<?php

namespace App\Http\Controllers\Api\RBAC;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Spatie\Permission\Models\Permission;

class PermissionController extends Controller
{
    public function index()
    {
        $perms = Permission::all();
        return response()->json([
            'success' => true,
            'data' => $perms,
            'message' => 'All permissions retrieved successfully.'
        ], 200);
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => [
                'required',
                'string',
                'max:255',
                Rule::unique('permissions')->where(function ($query) use ($request) {
                    return $query->where('guard_name', $request->guard_name);
                }),
            ],
            'guard_name' => 'required|string'
        ]);

        $perm = Permission::create($validated);

        return response()->json([
            'success' => true,
            'data' => $perm,
            'message' => 'a permission created successfully.'
        ], 201);
    }

    public function show($id)
    {
        $perm = Permission::findOrFail($id);
        return response()->json([
            'success' => true,
            'data' => $perm,
            'message' => 'requested permission retrieved successfully.',
        ]);
    }

    public function update(Request $request, $id)
    {
        $perm = Permission::findOrFail($id);

        $validated = $request->validate([
            'name' => [
                'required',
                'string',
                'max:255',
                Rule::unique('permissions', 'name')
                    ->ignore($id)
                    ->where(function ($query) use ($request) {
                        return $query->where('guard_name', $request->guard_name);
                    }),
            ],
            'guard_name' => 'required|string|max:255',
        ]);

        $perm->update($validated);

        return response()->json([
            'success' => true,
            'data' => $perm,
            'message' => 'permission updated successfully.',
        ], 200);
    }

    public function destroy($id)
    {
        $perm = Permission::findOrFail($id);
        $perm->delete();

        return response()->json([
            'success' => true,
            'message' => 'Permission deleted successfully.'
        ]);

    }
}
