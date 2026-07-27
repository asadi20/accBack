<?php
use App\Models\User;
use Laravel\Sanctum\Sanctum;
use Spatie\Permission\Models\Permission;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

describe('index', function () {
    it('returns all permissions', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Permission::create([
            'name' => 'users-view',
            'guard_name' => 'api'
        ]);

        Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $response = $this->getJson('/api/rbac/permissions');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'All permissions retrieved successfully.',
            ])
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'guard_name',
                        'created_at',
                        'updated_at',
                    ]
                ],
                'message'
            ])
            ->assertJsonCount(2, 'data')
            ->assertJsonFragment([
                'name' => 'users-view',
                'guard_name' => 'api'
            ])
            ->assertJsonFragment([
                'name' => 'users-create',
                'guard_name' => 'api'
            ]);
    });

    it('returns an empty list when no permissions exists', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $response = $this->getJson('/api/rbac/permissions');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [],
                'message' => 'All permissions retrieved successfully.'
            ])
            ->assertJsonCount(0, 'data');
    });

    it('prevents guests from viewing permissions', function () {
        $response = $this->getJson('/api/rbac/permissions');
        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.'
            ]);
    });
});

describe('store', function () {
    it('can store a new permission with valid data', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $payload = [
            'name' => 'users-delete',
            'guard_name' => 'api'
        ];

        $response = $this->postJson('/api/rbac/permissions', $payload);

        $response->assertStatus(201)
            ->assertJson([
                'success' => true,
                'data' => [
                    'name' => 'users-delete',
                    'guard_name' => 'api',
                ],
                'message' => 'a permission created successfully.'
            ])
            ->assertJsonStructure([
                'success',
                'data' => ['id', 'name', 'guard_name', 'created_at', 'updated_at'],
                'message'
            ]);

        $this->assertDatabaseHas('permissions', [
            'name' => 'users-delete',
            'guard_name' => 'api'
        ]);
    });

    it('prevents guests storing a permission', function () {
        $payload = [
            'name' => 'users-delete',
            'guard_name' => 'api'
        ];

        $response = $this->postJson('/api/rbac/permissions', $payload);

        $response->assertStatus(401); // unauthorized

        $this->assertDatabaseMissing('permissions', [
            'name' => 'users-delete'
        ]);
    });

    it('validates required fields when creating a permission', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        // send empty payload
        $response = $this->postJson('/api/rbac/permissions', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'guard_name']);
    });

    it('prevents creating a duplicate permission name for the same guard', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $payload = [
            'name' => 'users-create',
            'guard_name' => 'api'
        ];

        $response = $this->postJson('/api/rbac/permissions', $payload);
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    });

    it('allows creating the same permission name for different guards', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $payload = [
            'name' => 'users-create',
            'guard_name' => 'web'
        ];

        $response = $this->postJson('/api/rbac/permissions', $payload);
        $response->assertStatus(201);

        $this->assertDatabaseHas('permissions', [
            'name' => 'users-create',
            'guard_name' => 'web'
        ]);
    });

    it('validate maximum length of permission name', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $payload = [
            'name' => str_repeat('a', 256),
            'guard_name' => 'api'
        ];

        $response = $this->postJson('/api/rbac/permissions', $payload);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    });
});

describe('show', function () {
    it('returns a permissions by id', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $permission = Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $response = $this->getJson("/api/rbac/permissions/{$permission->id}");

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $permission->id,
                    'name' => 'users-create',
                    'guard_name' => 'api'
                ],
                'message' => 'requested permission retrieved successfully.'
            ])
            ->assertJsonStructure([
                'success',
                'data' => ['id', 'name', 'guard_name', 'created_at', 'updated_at'],
                'message'
            ]);
    });

    it('prevents guests from viewing a permission', function () {
        $permission = Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $response = $this->getJson("/api/rbac/permissions/{$permission->id}");
        $response->assertStatus(401);
    });

    it('returns not found for a missing permission', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $response = $this->getJson('/api/rbac/permissions/999');
        $response->assertStatus(404);
    });
});

describe('update', function () {
    it('updates a permission with valid data', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $permission = Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $payload = [
            'name' => 'users-view',
            'guard_name' => 'api'
        ];

        $response = $this->putJson("/api/rbac/permissions/{$permission->id}", $payload);

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $permission->id,
                    'name' => 'users-view',
                    'guard_name' => 'api'
                ],
                'message' => 'permission updated successfully.'
            ]);

        $this->assertDatabaseHas('permissions', [
            'id' => $permission->id,
            'name' => 'users-view',
            'guard_name' => 'api'
        ]);
    });

    it('prevents guests from updating a permission', function () {
        $permission = Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $payload = [
            'name' => 'users-view',
            'guard_name' => 'api'
        ];

        $response = $this->putJson("/api/rbac/permissions/{$permission->id}", $payload);

        $response->assertStatus(401);

        $this->assertDatabaseHas('permissions', [
            'id' => $permission->id,
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

    });

    it('validates required fields when updating a permission', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $permission = Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);


        $response = $this->putJson("/api/rbac/permissions/{$permission->id}", []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'guard_name']);
    });

    it('returns not found when the permission does not exist', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $payload = [
            'name' => 'users-view',
            'guard_name' => 'api'
        ];

        $response = $this->putJson("/api/rbac/permissions/999", $payload);

        $response->assertStatus(404);
    });

    it('allows keeping the same name for the same permission', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        $permission = Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $payload = [
            'name' => 'users-create',
            'guard_name' => 'api'
        ];

        $response = $this->putJson("/api/rbac/permissions/{$permission->id}", $payload);
        $response->assertStatus(200);

        $this->assertDatabaseHas('permissions', [
            'id' => $permission->id,
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);
    });

    it('prevents duplicate permission names for the same guard', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $permission = Permission::create([
            'name' => 'users-view',
            'guard_name' => 'api'
        ]);

        $payload = [
            'name' => 'users-create',
            'guard_name' => 'api'
        ];

        $response = $this->putJson("/api/rbac/permissions/{$permission->id}", $payload);
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name']);

        $this->assertDatabaseHas('permissions', [
            'id' => $permission->id,
            'name' => 'users-view',
            'guard_name' => 'api'
        ]);
    });

    it('allows the same permission name for different guards when updating', function () {
        $user = User::factory()->create();
        Sanctum::actingAs($user);

        Permission::create([
            'name' => 'users-create',
            'guard_name' => 'api'
        ]);

        $permission = Permission::create([
            'name' => 'users-view',
            'guard_name' => 'api'
        ]);

        $payload = [
            'name' => 'users-create',
            'guard_name' => 'web'
        ];

        $response = $this->putJson("/api/rbac/permissions/{$permission->id}", $payload);
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $permission->id,
                    'name' => 'users-create',
                    'guard_name' => 'web'
                ],
                'message' => 'permission updated successfully.'
            ]);

        $this->assertDatabaseHas('permissions', [
            'id' => $permission->id,
            'name' => 'users-create',
            'guard_name' => 'web'
        ]);
    });
});
