#pragma once

#include <cmath>

struct Vector3 {
    float X;
    float Y;
    float Z;
    
    Vector3() : X(0), Y(0), Z(0) {}
    Vector3(float x, float y, float z) : X(x), Y(y), Z(z) {}
    
    // Vector operations
    Vector3 operator+(const Vector3& other) const {
        return Vector3(X + other.X, Y + other.Y, Z + other.Z);
    }
    
    Vector3 operator-(const Vector3& other) const {
        return Vector3(X - other.X, Y - other.Y, Z - other.Z);
    }
    
    Vector3 operator*(float scalar) const {
        return Vector3(X * scalar, Y * scalar, Z * scalar);
    }
    
    Vector3 operator/(float scalar) const {
        if (scalar == 0) return Vector3();
        float inv = 1.0f / scalar;
        return Vector3(X * inv, Y * inv, Z * inv);
    }
    
    // Dot product
    float Dot(const Vector3& other) const {
        return X * other.X + Y * other.Y + Z * other.Z;
    }
    
    // Cross product
    Vector3 Cross(const Vector3& other) const {
        return Vector3(
            Y * other.Z - Z * other.Y,
            Z * other.X - X * other.Z,
            X * other.Y - Y * other.X
        );
    }
    
    // Magnitude (length) of the vector
    float Magnitude() const {
        return std::sqrt(X * X + Y * Y + Z * Z);
    }
    
    // Distance to another vector
    float Distance(const Vector3& other) const {
        return (*this - other).Magnitude();
    }
    
    // Normalize the vector (make it unit length)
    Vector3 Normalize() const {
        float mag = Magnitude();
        if (mag == 0) return Vector3();
        return *this / mag;
    }
    
    // Check if vector is zero
    bool IsZero() const {
        return X == 0 && Y == 0 && Z == 0;
    }
    
    // Convert to string for debugging
    const char* ToString() const {
        static char buffer[100];
        snprintf(buffer, sizeof(buffer), "X: %.2f, Y: %.2f, Z: %.2f", X, Y, Z);
        return buffer;
    }
};
