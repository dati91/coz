/* Simulated "shapes" block: OOP with a two-level inheritance hierarchy and
 * virtual dispatch, to exercise --fixed-symbol against class methods
 * (mangled names, overrides sharing a plain method name across classes). */
#include <memory>
#include <vector>

class Shape {
public:
  explicit Shape(int id) : _id(id) {}
  virtual ~Shape() {}

  virtual double compute_area(int iterations) const = 0;

  // Inline accessor - usually fully inlined at call sites, so it may not
  // even have its own out-of-line DWARF subprogram at -O2.
  inline int id() const { return _id; }

private:
  int _id;
};

// Abstract mid-level class - multi-level inheritance base for Square/Rectangle.
class Quadrilateral : public Shape {
public:
  explicit Quadrilateral(int id) : Shape(id) {}

  // Shared helper all quadrilaterals use - a second virtual method, so
  // Square/Rectangle each get their own override sharing this same plain name.
  virtual double side_product(int iterations) const = 0;

  double compute_area(int iterations) const override {
    return side_product(iterations);
  }
};

class Square : public Quadrilateral {
public:
  explicit Square(double side) : Quadrilateral(2), _side(side) {}

  double side_product(int iterations) const override {
    volatile double area = 0;
    for (int i = 0; i < iterations; i++) {
      area += _side * _side;
    }
    return area;
  }

private:
  double _side;
};

class Rectangle : public Quadrilateral {
public:
  Rectangle(double width, double height) : Quadrilateral(3), _width(width), _height(height) {}

  double side_product(int iterations) const override {
    volatile double area = 0;
    for (int i = 0; i < iterations; i++) {
      area += _width * _height;
    }
    return area;
  }

private:
  double _width;
  double _height;
};

class Circle : public Shape {
public:
  explicit Circle(double radius) : Shape(1), _radius(radius) {}

  double compute_area(int iterations) const override {
    volatile double area = 0;
    for (int i = 0; i < iterations; i++) {
      area += 3.14159265358979 * _radius * _radius;
    }
    return area;
  }

private:
  double _radius;
};

extern "C" void run_block() {
  std::vector<std::unique_ptr<Shape>> shapes;
  shapes.emplace_back(new Circle(2.0));
  shapes.emplace_back(new Square(3.0));
  shapes.emplace_back(new Rectangle(4.0, 5.0));

  volatile double total = 0;
  for (const auto& shape : shapes) {
    total += shape->compute_area(20000) * (shape->id() > 0 ? 1 : 0) + shape->id();
  }
}
