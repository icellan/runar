use runar::prelude::*;

#[runar::contract]
struct SchnorrZKP {
    #[readonly]
    pub_key: Point,
}

#[runar::methods(SchnorrZKP)]
impl SchnorrZKP {
    #[public]
    fn verify(&self, r_point: &Point, s: Bigint) {
        assert!(ec_on_curve(r_point));
        let e = bin2num(&hash256(&cat(r_point, &self.pub_key)));
        let s_g = ec_mul_gen(s);
        let e_p = ec_mul(&self.pub_key, e);
        let rhs = ec_add(r_point, &e_p);
        assert!(ec_point_x(&s_g) == ec_point_x(&rhs));
        assert!(ec_point_y(&s_g) == ec_point_y(&rhs));
    }
}
