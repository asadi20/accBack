<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\Sanctum;
use Spatie\Permission\Models\Role;

uses(RefreshDatabase::class);

describe('index', function () {
    it('returns all roles for authenticated users', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Role::create(['name' => 'admin', 'guard_name' => 'api']);
        Role::create(['name' => 'supervisor', 'guard_name' => 'api']);

        $response = $this->getJson('/api/rbac/roles');
        $response
            ->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    ['name' => 'admin', 'guard_name' => 'api'],
                    ['name' => 'supervisor', 'guard_name' => 'api'],
                ],
                'message' => 'all roles retrieved successfully.',
            ])
            ->assertJsonStructure([
                'success',
                'data' => ['*' => ['id', 'name', 'guard_name', 'created_at', 'updated_at']],
                'message',
            ])
            ->assertJsonCount(2, 'data');
    });

    it('blocks unauthenticated users from listing roles', function () {
        Role::create([
            'name' => 'admin',
            'guard_name' => 'api',
        ]);

        $response = $this->getJson('/api/rbac/roles');
        $response->assertStatus(401);
    });

    it('returns an empty list when no roles exist', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $response = $this->getJson('/api/rbac/roles');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [],
                'message' => 'all roles retrieved successfully.',
            ])
            ->assertJsonCount(0, 'data');
    });
});

describe('store', function () {
    it('stores a validated role successfully', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $payload = [
            'name' => 'admin',
            'guard_name' => 'api',
        ];

        $response = $this->postJson('/api/rbac/roles', $payload);
        $response
            ->assertStatus(201)
            ->assertJson([
                'success' => true,
                'data' => [
                    'name' => 'admin',
                    'guard_name' => 'api',
                ],
                'message' => 'New Role added to system.',
            ])
            ->assertJsonStructure([
                'success',
                'data' => ['id', 'name', 'guard_name', 'created_at', 'updated_at'],
                'message',
            ]);

        $this->assertDatabaseHas('roles', [
            'name' => 'admin',
            'guard_name' => 'api',
        ]);
    });

    it('prevents guests from storing a role', function () {
        $payload = [
            'name' => 'admin',
            'guard_name' => 'api',
        ];

        $response = $this->postJson('/api/rbac/roles', $payload);

        $response->assertStatus(401);

        $this->assertDatabaseMissing('roles', [
            'name' => 'admin',
            'guard_name' => 'api',
        ]);
    });

    it('validates required fields when creating a role', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $response = $this->postJson('/api/rbac/roles', []);
        $response
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'guard_name']);
    });

    it('prevents creating a duplicate role name for the same guard', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Role::create([
            'name' => 'admin',
            'guard_name' => 'api',
        ]);

        $payload = [
            'name' => 'admin',
            'guard_name' => 'api',
        ];

        $response = $this->postJson('/api/rbac/roles', $payload);
        $response
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    });

    it('allows creating the same role name for different guards', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Role::create([
            'name' => 'admin',
            'guard_name' => 'api',
        ]);

        $payload = [
            'name' => 'admin',
            'guard_name' => 'web',
        ];

        $response = $this->postJson('/api/rbac/roles', $payload);
        $response
            ->assertStatus(201)
            ->assertJson([
                'success' => true,
                'data' => ['name' => 'admin', 'guard_name' => 'web'],
                'message' => 'New Role added to system.',
            ]);

        $this->assertDatabaseHas('roles', [
            'name' => 'admin',
            'guard_name' => 'web',
        ]);
    });

    it('validates maximum length of role name', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $payload = [
            'name' => str_repeat('a', 256),
            'guard_name' => 'api',
        ];

        $response = $this->postJson('/api/rbac/roles', $payload);
        $response->assertStatus(422)->assertJsonValidationErrors(['name']);
    });
});
